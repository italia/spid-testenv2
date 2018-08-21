# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import os.path
import random
import string
from collections import namedtuple
from datetime import datetime
from hashlib import sha1
from logging.handlers import RotatingFileHandler

from flask import Response, abort, escape, redirect, render_template, request, session, url_for
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.assertion import filter_on_demands
from saml2.attribute_converter import list_to_local
from saml2.config import Config as Saml2Config
from saml2.entity import UnknownBinding
from saml2.metadata import create_metadata_string
from saml2.response import IncorrectlySigned
from saml2.s_utils import UnknownSystemEntity, UnsupportedBinding
from saml2.saml import NAME_FORMAT_BASIC, NAMEID_FORMAT_TRANSIENT, Attribute, Issuer
from saml2.samlp import LogoutRequest
from saml2.sigver import verify_redirect_signature
from saml2.server import Server

from testenv.crypto import HTTPPostSignatureVerifier, HTTPRedirectSignatureVerifier, sign_http_post, sign_http_redirect
from testenv.exceptions import BadConfiguration, DeserializationError, RequestParserError, SignatureVerificationError
from testenv.parser import (
    HTTPPostRequestParser, HTTPRedirectRequestParser, get_http_post_request_deserializer,
    get_http_redirect_request_deserializer,
)
from testenv.settings import ALLOWED_SIG_ALGS, AUTH_NO_CONSENT, DIGEST_ALG, SIGN_ALG, SPID_LEVELS, STATUS_SUCCESS
from testenv.spid import SpidPolicy, ac_factory
from testenv.users import JsonUserManager
from testenv.utils import get_spid_error, prettify_xml
from testenv.saml import create_logout_response, create_response, create_error_response
from testenv.crypto import sign_http_post, sign_http_redirect

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

# FIXME: move to a the parser.py module after metadata refactoring
SPIDRequest = namedtuple('SPIDRequest', ['data', 'saml_tree'])


class IdpServer(object):

    ticket = {}
    responses = {}
    challenges = {}
    _binding_mapping = {
        'http-redirect': BINDING_HTTP_REDIRECT,
        'http-post': BINDING_HTTP_POST
    }
    _endpoint_types = ['single_sign_on_service', 'single_logout_service']
    _spid_levels = SPID_LEVELS
    _spid_attributes = {
        'primary': {
            'spidCode': 'string',
            'name': 'string',
            'familyName': 'string',
            'placeOfBirth': 'string',
            'countryOfBirth': 'string',
            'dateOfBirth': 'date',
            'gender': 'string',
            'companyName': 'string',
            'registeredOffice': 'string',
            'fiscalNumber': 'string',
            'ivaCode': 'string',
            'idCard': 'string',
        },
        'secondary': {
            'mobilePhone': 'string',
            'email': 'string',
            'address': 'string',
            'expirationDate': 'date',
            'digitalAddress': 'string'
        }
    }
    # digitalAddress => PEC
    CHALLENGES_TIMEOUT = 30  # seconds
    SAML_VERSION = '2.0'

    def __init__(self, app, config, *args, **kwargs):
        """
        :param app: Flask instance
        :param config: dictionary containing the configuration
        :param args:
        :param kwargs:
        """
        # bind Flask app
        self.app = app
        self.user_manager = JsonUserManager(config=config)
        # setup
        self._config = config
        self.app.secret_key = 'sosecret'
        handler = RotatingFileHandler(
            'spid.log', maxBytes=500000, backupCount=1
        )
        self.app.logger.addHandler(handler)
        self._prepare_server()

    @property
    def _mode(self):
        return 'https' if self._config.get('https', False) else 'http'

    def _idp_config(self):
        """
        Process pysaml2 configuration
        """
        key_file_path = self._config.get('key_file')
        cert_file_path = self._config.get('cert_file')
        metadata = self._config.get('metadata')
        metadata = metadata if metadata else []
        if metadata:
            for typ in ['local', 'remote']:
                if metadata.get(typ) is None:
                    metadata[typ] = []
        existing_key = os.path.isfile(key_file_path) if key_file_path else None
        existing_cert = os.path.isfile(cert_file_path) \
            if cert_file_path else None
        if not existing_key:
            raise BadConfiguration(
                'Chiave privata dell\'IdP di test non'\
                ' trovata: {} non trovato'.format(key_file_path)
            )
        if not existing_cert:
            raise BadConfiguration(
                'Certificato dell\'IdP di test non'\
                ' trovato: {} non trovato'.format(cert_file_path)
            )
        self.entity_id = self._config.get('base_url')
        if not self.entity_id:
            raise BadConfiguration(
                'base_url non impostato!'
            )
        idp_conf = {
            'entityid': self.entity_id,
            'description': 'Spid Test IdP',
            'service': {
                'idp': {
                    'name': 'Spid Testenv',
                    'endpoints': {
                        'single_sign_on_service': [
                        ],
                        'single_logout_service': [
                        ],
                    },
                    'policy': {
                        'default': {
                            'name_form': NAME_FORMAT_BASIC,
                        },
                    },
                    'name_id_format': [
                        NAMEID_FORMAT_TRANSIENT,
                    ]
                },
            },
            'debug': 1,
            'key_file': self._config.get('key_file'),
            'cert_file': self._config.get('cert_file'),
            'metadata': metadata,
            'logger': {
                'rotating': {
                    'filename': 'idp.log',
                    'maxBytes': 500000,
                    'backupCount': 1,
                },
                'loglevel': 'debug',
            }
        }
        # setup services url
        for _service_type in self._endpoint_types:
            endpoint = self._config['endpoints'][_service_type]
            idp_conf['service']['idp']['endpoints'][_service_type].append(
                (
                    '{}{}'.format(self.entity_id, endpoint),
                    BINDING_HTTP_REDIRECT
                )
            )
            idp_conf['service']['idp']['endpoints'][_service_type].append(
                (
                    '{}{}'.format(self.entity_id, endpoint),
                    BINDING_HTTP_POST
                )
            )
        return idp_conf

    def _setup_app_routes(self):
        """
        Setup Flask routes
        """
        # Setup SSO and SLO endpoints
        endpoints = self._config.get('endpoints')
        if endpoints:
            for ep_type in self._endpoint_types:
                _url = endpoints.get(ep_type)
                if _url:
                    if not _url.startswith('/'):
                        raise BadConfiguration(
                            'Errore nella configurazione delle url,'\
                            ' i path devono essere relativi ed iniziare'\
                            ' con "/" (slash) - url {}'.format(_url)
                        )
                    for _binding in self._binding_mapping.keys():
                        self.app.add_url_rule(
                            _url,
                            ep_type,
                            getattr(self, ep_type),
                            methods=['GET', 'POST']
                        )
        self.app.add_url_rule('/', 'index', self.index, methods=['GET'])
        self.app.add_url_rule(
            '/login', 'login', self.login, methods=['POST', 'GET']
        )
        # Endpoint for user add action
        self.app.add_url_rule(
            '/users', 'users', self.users, methods=['GET', 'POST']
        )
        self.app.add_url_rule(
            '/continue-response', 'continue_response',
            self.continue_response, methods=['POST']
        )
        self.app.add_url_rule(
            '/metadata', 'metadata', self.metadata, methods=['POST', 'GET']
        )

    def _prepare_server(self):
        """
        Setup server
        """
        self.idp_config = Saml2Config()
        self.BASE = '{}://{}:{}'.format(
            self._mode, self._config.get('host'), self._config.get('port')
        )
        if 'entityid' not in self._config:
            # as fallback for entityid use host:port string
            self._config['entityid'] = self.BASE
        self.idp_config.load(cnf=self._idp_config())
        # TODO: remove this
        setattr(
            self.idp_config,
            'attribute_converters',
            ac_factory(
                'testenv/attributemaps',
                **{'override_types': self._all_attributes}
            )
        )
        self.server = Server(config=self.idp_config)
        self._setup_app_routes()

    def _verify_spid(self, level, verify=False, **kwargs):
        """
        :param level: integer, SPID level
        :param verify: boolean, if True verify
            spid extra challenge (otp etc.), if False prepare the challenge
        :param kwargs: dictionary, extra arguments
        """
        level = self._spid_levels.index(level)
        self.app.logger.debug('spid level {} - verifica ({})'.format(level, verify))
        if verify:
            # Verify the challenge
            if level == 2:
                # spid level 2
                otp = kwargs.get('data').get('otp')
                key = kwargs.get('key')
                if key and key not in self.challenges or not otp:
                    return False
                total_seconds = (
                    datetime.now() - self.challenges[key][1]
                ).total_seconds()
                # Check that opt value is equal and not expired
                _is_expired = total_seconds > self.CHALLENGES_TIMEOUT
                if self.challenges[key][0] != otp or _is_expired:
                    del self.challenges[key]
                    return False
            return True
        else:
            # Prepare the challenge
            if level == 2:
                # spid level 2
                # very simple otp implementation,
                # while opt is a random 6 digits string
                # with a lifetime setup in the server instance
                key = kwargs.get('key')
                otp = ''.join(random.choice(string.digits) for _ in range(6))
                self.challenges[key] = [otp, datetime.now()]
                extra_challenge = '<span>Otp ({})</span>'\
                '<input type="text" name="otp" />'.format(
                    otp
                )
            else:
                extra_challenge = ''
            return extra_challenge

    def unpack_args(self, elems):
        """
        Unpack arguments from request
        """
        return dict([(k, v) for k, v in elems.items()])

    def _raise_error(self, msg, extra=None):
        """
        Raise some error using 'abort' function from Flask

        :param msg: string for error type
        :param extra: optional string for error details
        """

        abort(
            Response(
               render_template(
                    "error.html",
                    **{'msg': msg, 'extra': extra or ""}
                ), 200
            )
        )

    def _store_request(self, authnreq):
        """
        Store authnrequest in a dictionary

        :param authnreq: authentication request string
        """
        self.app.logger.debug('store_request: {}'.format(authnreq))
        # FIXME: improve this
        from lxml.etree import tostring
        key = sha1(tostring(authnreq._xml_doc)).hexdigest()
        # store the AuthnRequest
        self.ticket[key] = authnreq
        return key

    def _handle_errors(self, xmlstr, errors=None):
        rendered_error_response = render_template(
            'spid_error.html',
            **{
                'lines': xmlstr.splitlines(),
                'errors': errors
                }
            )
        return rendered_error_response

    def _parse_message(self, action):
        """
        Parse an AuthnRequest or a LogoutRequest

        :param action: type of request
        """
        method = request.method

        if method == 'GET':
            return self._handle_http_redirect(action)
        elif method == 'POST':
            return self._handle_http_post(action)
        else:
            self._raise_error(
                'I metodi consentiti sono'
                ' GET (Http-Redirect) o POST (Http-Post)'
            )

    def _handle_http_redirect(self, action):
        # FIXME: replace the following code with a call to a function
        # in the parser.py module after metadata refactoring.
        # The IdpServer class should not
        # be responsible of request parsing, or know anything
        # about request parsing *at all*.
        saml_msg = self.unpack_args(request.args)
        request_data = HTTPRedirectRequestParser(saml_msg).parse()
        deserializer = get_http_redirect_request_deserializer(
            request_data, action, self.server.metadata)
        saml_tree = deserializer.deserialize()
        certs = self._get_certificates_by_issuer(saml_tree.issuer.text)
        for cert in certs:
            HTTPRedirectSignatureVerifier(cert, request_data).verify()
        return SPIDRequest(request_data, saml_tree)

    def _handle_http_post(self, action):
        # FIXME: replace the following code with a call to a function
        # in the parser.py module after metadata refactoring.
        # The IdpServer class should not
        # be responsible of request parsing, or know anything
        # about request parsing *at all*.
        saml_msg = self.unpack_args(request.form)
        request_data = HTTPPostRequestParser(saml_msg).parse()
        deserializer = get_http_post_request_deserializer(
            request_data, action, self.server.metadata)
        saml_tree = deserializer.deserialize()
        certs = self._get_certificates_by_issuer(saml_tree.issuer.text)
        for cert in certs:
            HTTPPostSignatureVerifier(cert, request_data).verify()
        return SPIDRequest(request_data, saml_tree)

    def _get_certificates_by_issuer(self, issuer):
        try:
            return self.server.metadata.certs(issuer, 'any', 'signing')
        except KeyError:
            self._raise_error(
                'entity ID {} non registrato, impossibile ricavare'\
                ' un certificato valido.'.format(issuer)
            )

    def single_sign_on_service(self):
        """
        Process Http-Redirect or Http-POST request

        :param request: Flask request object
        """
        # TODO: handle errors in FE
        try:
            spid_request = self._parse_message(action='login')
            self.app.logger.debug(
                'AuthnRequest: \n{}'.format(spid_request.data.saml_request)
            )
            issuer_name = spid_request.saml_tree.issuer.text
            if issuer_name and issuer_name not in self.server.metadata.service_providers():
                raise UnknownSystemEntity
            # Perform login
            key = self._store_request(spid_request.saml_tree)
            session['request_key'] = key
            session['relay_state'] = spid_request.data.relay_state or ''
            return redirect(url_for('login'))
        except RequestParserError as err:
            self._raise_error(str(err))
        except SignatureVerificationError as err:
            self._raise_error(str(err))
        except DeserializationError as err:
            return self._handle_errors(err.initial_data, err.details)

    @property
    def _spid_main_fields(self):
        """
        Returns a list of spid main attributes
        """
        return self._spid_attributes['primary'].keys()

    @property
    def _spid_secondary_fields(self):
        """
        Returns a list of spid secondary attributes
        """
        return self._spid_attributes['secondary'].keys()

    @property
    def _all_attributes(self):
        _dct = self._spid_attributes['primary'].copy()
        _dct.update(self._spid_attributes['secondary'])
        return _dct

    def users(self):
        """
        Add user endpoint
        """
        spid_main_fields = self._spid_main_fields
        spid_secondary_fields = self._spid_secondary_fields
        rendered_form = render_template(
            "users.html",
            **{
                'action': '/users',
                'primary_attributes': spid_main_fields,
                'secondary_attributes': spid_secondary_fields,
                'users': self.user_manager.all(),
                'sp_list': self.server.metadata.service_providers()
            }
        )
        if request.method == 'GET':
            return rendered_form, 200
        elif request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            sp = request.form.get('service_provider')
            if not sp:
                sp = None
            if not username or not password:
                abort(400)
            extra = {}
            for spid_field in spid_main_fields:
                spid_value = request.form.get(spid_field)
                if spid_value:
                    extra[spid_field] = spid_value
            for spid_field in spid_secondary_fields:
                spid_value = request.form.get(spid_field)
                if spid_value:
                    extra[spid_field] = spid_value
            self.user_manager.add(username, password, sp, extra)
        return 'Added a new user', 200

    def index(self):
        rendered_form = render_template(
            "home.html",
            **{
                'sp_list': [
                    {
                        "name": sp, "spId": sp
                    } for sp in self.server.metadata.service_providers()
                ],
            }
        )
        return rendered_form, 200

    def get_destination(self, req, sp_id):
        destination = None
        acs_index = getattr(req, 'assertion_consumer_service_index', None)
        if acs_index is not None:
            acss = self.server.metadata.assertion_consumer_service(
                sp_id, req.protocol_binding
            )
            for acs in acss:
                if acs.get('index') == acs_index:
                    destination = acs.get('location')
                    break
            self.app.logger.debug(
                'AssertionConsumerServiceIndex Location: {}'.format(
                    destination
                )
            )
        if destination is None:
            destination = req.assertion_consumer_service_url
            self.app.logger.debug(
                'AssertionConsumerServiceURL: {}'.format(
                    destination
                )
            )
        return destination

    def login(self):
        """
        Login endpoint (verify user credentials)
        """
        def from_session(key):
            return session[key] if key in session else None
        key = from_session('request_key')
        relay_state = from_session('relay_state')
        self.app.logger.debug('Request key: {}'.format(key))
        if key and key in self.ticket:
            authn_request = self.ticket[key]
            sp_id = authn_request.issuer.text
            destination = self.get_destination(authn_request, sp_id)
            authn_context = authn_request.requested_authn_context
            spid_level = authn_context.authn_context_class_ref.text
            if request.method == 'GET':
                # inject extra data in form login based on spid level
                extra_challenge = self._verify_spid(level=spid_level, **{'key': key})
                rendered_form = render_template(
                    'login.html',
                    **{
                        'action': url_for('login'),
                        'request_key': key,
                        'relay_state': relay_state,
                        'extra_challenge': extra_challenge
                    }
                )
                return rendered_form, 200

            if 'confirm' in request.form:
                # verify optional challenge based on spid level
                verified = self._verify_spid(
                    level=spid_level,
                    verify=True, **{
                        'key': key, 'data': request.form
                    }
                )
                if verified:
                    # verify user credentials
                    user_id, user = self.user_manager.get(
                        request.form['username'],
                        request.form['password'],
                        sp_id
                    )
                    if user_id is not None:
                        # setup response
                        identity = user['attrs'].copy()
                        # AUTHN = {
                        #     "class_ref": spid_level,
                        #     "authn_auth": spid_level
                        # }
                        self.app.logger.debug(
                            'Unfiltered data: {}'.format(identity)
                        )
                        atcs_idx = getattr(authn_request, 'attribute_consuming_service_index', None)
                        self.app.logger.debug(
                            'AttributeConsumingServiceIndex: {}'.format(
                                atcs_idx
                            )
                        )
                        if atcs_idx:
                            # TODO: Remove this pysaml2 dependency
                            attrs = self.server.wants(sp_id, atcs_idx)
                            required = [
                                Attribute(
                                    name=el.get('name'),
                                    friendly_name=None,
                                    name_format=NAME_FORMAT_BASIC
                                ) for el in attrs.get('required')
                            ]
                            optional = [
                                Attribute(
                                    name=el.get('name'),
                                    friendly_name=None,
                                    name_format=NAME_FORMAT_BASIC
                                ) for el in attrs.get('optional')
                            ]
                            acs = ac_factory(
                                './testenv/attributemaps',
                                **{'override_types': self._all_attributes}
                            )
                            rava = list_to_local(acs, required)
                            oava = list_to_local(acs, optional)
                        else:
                            rava = {}
                            oava = {}
                        self.app.logger.debug(
                            'Required attributes: {}'.format(rava)
                        )
                        self.app.logger.debug(
                            'Optional attributes: {}'.format(oava)
                        )
                        identity = filter_on_demands(
                            identity, rava, oava
                        )
                        self.app.logger.debug(
                            'Filtered data: {}'.format(identity)
                        )

                        for k,v in identity.items():
                            if k in self._spid_main_fields:
                                _type = self._spid_attributes['primary'][k]
                            else:
                                _type = self._spid_attributes['secondary'][k]
                            identity[k] = (_type, v)

                        response_xmlstr = create_response(
                            {
                                'response': {
                                    'attrs': {
                                        'in_response_to': authn_request.id,
                                        'destination': destination
                                    }
                                },
                                'issuer': {
                                    'attrs': {
                                        'name_qualifier': self.server.config.entityid,
                                    },
                                    'text': self.server.config.entityid
                                },
                                'name_id': {
                                    'attrs': {
                                        'name_qualifier': self.server.config.entityid,
                                    }
                                },

                                'subject_confirmation_data': {
                                    'attrs': {
                                        'recipient': destination
                                    }
                                },
                                'audience': {
                                    'text': sp_id
                                },
                                'authn_context_class_ref': {
                                    'text': spid_level
                                }
                            },
                            {
                                'status_code': STATUS_SUCCESS
                            },
                            identity
                        ).to_xml()
                        key_file = self.server.config.key_file
                        cert_file = self.server.config.cert_file

                        pkey = open(key_file, 'rb').read()
                        cert = open(cert_file, 'rb').read()
                        response = sign_http_post(response_xmlstr, pkey, cert)
                        self.app.logger.debug(
                            'Response: \n{}'.format(response)
                        )
                        rendered_template = render_template(
                            'form_http_post.html',
                            **{
                                'action': destination,
                                'relay_state': relay_state,
                                'message': response,
                                'message_type': 'SAMLResponse'
                            }
                        )
                        self.responses[key] = rendered_template
                        # Setup confirmation page data
                        rendered_response = render_template(
                            'confirm.html',
                            **{
                                'destination_service': sp_id,
                                'lines': escape(
                                    response_xmlstr.decode('ascii')
                                ).splitlines(),
                                'attrs': identity.keys(),
                                'action': '/continue-response',
                                'request_key': key
                            }
                        )
                        return rendered_response, 200
            elif 'delete' in request.form:
                error_info = get_spid_error(
                    AUTH_NO_CONSENT
                )
                response = create_error_response(
                    {
                        'response': {
                            'attrs': {
                                'in_response_to': authn_request.id,
                                'destination': destination
                            }
                        },
                        'issuer': {
                            'attrs': {
                                'name_qualifier': self.server.config.entityid,
                            },
                            'text': self.server.config.entityid
                        },
                    },
                    {
                        'status_code': error_info[0],
                        'status_message': error_info[1]
                    }
                ).to_xml()
                self.app.logger.debug(
                    'Error response: \n{}'.format(response)
                )
                key_file = self.server.config.key_file
                cert_file = self.server.config.cert_file

                pkey = open(key_file, 'rb').read()
                cert = open(cert_file, 'rb').read()
                response = sign_http_post(response, pkey, cert)
                del self.ticket[key]
                rendered_template = render_template(
                    'form_http_post.html',
                    **{
                        'action': destination,
                        'relay_state': relay_state,
                        'message': response,
                        'message_type': 'SAMLResponse'
                    }
                )
                return rendered_template, 200
        return render_template('403.html'), 403

    def continue_response(self):
        key = request.form['request_key']
        if key and key in self.responses:
            _response = self.responses.pop(key)
            auth_req = self.ticket.pop(key)
            if 'confirm' in request.form:
                return _response, 200
            elif 'delete' in request.form:
                destination = self.get_destination(
                    auth_req, auth_req.issuer.text
                )
                error_info = get_spid_error(
                        AUTH_NO_CONSENT
                    )
                response = create_error_response(
                    {
                        'response': {
                            'attrs': {
                                'in_response_to': authn_req.id,
                                'destination': destination
                            }
                        },
                        'issuer': {
                            'attrs': {
                                'name_qualifier': 'something',
                            },
                            'text': self.server.config.entityid
                        },
                    },
                    {
                        'status_code': error_info[0],
                        'status_message': error_info[1]
                    }
                ).to_xml()
                self.app.logger.debug(
                    'Error response: \n{}'.format(response)
                )
                key_file = self.server.config.key_file
                cert_file = self.server.config.cert_file

                pkey = open(key_file, 'rb').read()
                cert = open(cert_file, 'rb').read()
                response = sign_http_post(response, pkey, cert)
                rendered_template = render_template(
                    'form_http_post.html',
                    **{
                        'action': destination,
                        'relay_state': relay_state,
                        'message': response,
                        'message_type': 'SAMLResponse'
                    }
                )
                return rendered_template, 200
        return render_template('403.html'), 403

    def _sp_single_logout_service(self, issuer_name):
        _slo = None
        for binding in [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT]:
            try:
                _slo = self.server.metadata.single_logout_service(
                    issuer_name, binding=binding, typ='spsso'
                )
            except UnsupportedBinding:
                pass
        return _slo

    def single_logout_service(self):
        """
        SLO endpoint
        """

        self.app.logger.debug("req: '%s'", request)
        try:
            spid_request = self._parse_message(action='logout')
            self.app.logger.debug(
                'LogoutRequest: \n{}'.format(
                    prettify_xml(req_info._xml_doc)
                )
            )
            issuer_name = spid_request.saml_tree.issuer.text
            # TODO: retrieve the following data from some custom structure
            _slo = self._sp_single_logout_service(issuer_name)
            if _slo is None:
                self._raise_error(
                    'Impossibile trovare un servizio di'\
                    ' Single Logout per il service provider {}'.format(
                        issuer_name
                    )
                )
            response_binding = _slo[0].get('binding')
            self.app.logger.debug(
                'Response binding: \n{}'.format(
                    response_binding
                )
            )
            destination = _slo[0].get('location')
            response = create_logout_response(
                {
                    'logout_response': {
                        'attrs': {
                            'in_response_to': req_info.id,
                            'destination': destination
                        }
                    },
                    'issuer': {
                        'attrs': {
                            'name_qualifier': 'something',
                        },
                        'text': self.server.config.entityid
                    }
                },
                {
                    'status_code': STATUS_SUCCESS
                }
            ).to_xml()
            key_file = self.server.config.key_file
            cert_file = self.server.config.cert_file
            key = open(key_file, 'rb').read()
            cert = open(cert_file, 'rb').read()
            relay_state = spid_request.data.relay_state or ''
            if response_binding == BINDING_HTTP_POST:
                response = sign_http_post(response, key, cert)
                rendered_template = render_template(
                    'form_http_post.html',
                    **{
                        'action': destination,
                        'relay_state': relay_state,
                        'message': response,
                        'message_type': 'SAMLResponse'
                    }
                )
                return rendered_template, 200
            elif response_binding == BINDING_HTTP_REDIRECT:
                query_string = sign_http_redirect(response, key, relay_state)
                location = '{}?{}'.format(destination, query_string)
                if location:
                    return redirect(location)
        except RequestParserError as err:
            self._raise_error(str(err))
        except SignatureVerificationError as err:
            self._raise_error(str(err))
        except DeserializationError as err:
            return self._handle_errors(err.initial_data, err.details)
        abort(400)

    def metadata(self):
        # TODO: generate from some custom logic
        metadata = create_metadata_string(
            __file__,
            self.server.config,
        )
        return Response(metadata, mimetype='text/xml')

    @property
    def _wsgiconf(self):
        _cnf = {
            'host': self._config.get('host', '0.0.0.0'),
            'port': self._config.get('port', '8000'),
            'debug': self._config.get('debug', True),
        }
        if self._config.get('https', False):
            key = self._config.get('https_key_file')
            cert = self._config.get('https_cert_file')
            if not key or not cert:
                raise KeyError(
                    'Errore modalità https: Chiave e/o certificato assenti!'
                )
            _cnf['ssl_context'] = (cert, key,)
        return _cnf

    def start(self):
        """
        Start the server instance
        """
        self.app.run(
            **self._wsgiconf
        )
