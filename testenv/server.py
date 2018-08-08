# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import os.path
import random
import string
from datetime import datetime
from hashlib import sha1
from logging.handlers import RotatingFileHandler

from flask import (Response, abort, escape, redirect, render_template,
                   render_template_string, request, session, url_for)
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.assertion import filter_on_demands
from saml2.attribute_converter import list_to_local
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from saml2.config import Config as Saml2Config
from saml2.entity import UnknownBinding
from saml2.metadata import create_metadata_string
from saml2.response import IncorrectlySigned
from saml2.s_utils import UnknownSystemEntity, UnsupportedBinding
from saml2.saml import NAME_FORMAT_BASIC, NAMEID_FORMAT_TRANSIENT, Attribute
from saml2.sigver import verify_redirect_signature
from testenv.exceptions import BadConfiguration
from testenv.parser import SpidParser
from testenv.settings import (ALLOWED_SIG_ALGS, AUTH_NO_CONSENT, DIGEST_ALG,
                              SIGN_ALG, SPID_LEVELS, spid_error_table)
from testenv.spid import SpidPolicy, SpidServer, ac_factory
from testenv.users import JsonUserManager
from testenv.utils import get_spid_error, prettify_xml

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'


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
            'spidCode': 'xs:string',
            'name': 'xs:string',
            'familyName': 'xs:string',
            'placeOfBirth': 'xs:string',
            'countryOfBirth': 'xs:string',
            'dateOfBirth': 'xs:date',
            'gender': 'xs:string',
            'companyName': 'xs:string',
            'registeredOffice': 'xs:string',
            'fiscalNumber': 'xs:string',
            'ivaCode': 'xs:string',
            'idCard': 'xs:string',
        },
        'secondary': {
            'mobilePhone': 'xs:string',
            'email': 'xs:string',
            'address': 'xs:string',
            'expirationDate': 'xs:date',
            'digitalAddress': 'xs:string'
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
        self.spid_parser = SpidParser()

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
        setattr(
            self.idp_config,
            'attribute_converters',
            ac_factory(
                'testenv/attributemaps',
                **{'override_types': self._all_attributes}
            )
        )
        self.server = SpidServer(config=self.idp_config)
        self._setup_app_routes()
        # setup custom methods in order to
        # prepare the login form and verify the challenge (optional)
        # for every spid level (1-2-3)
        self.authn_broker = AuthnBroker()
        for index, _level in enumerate(self._spid_levels):
            self.authn_broker.add(
                authn_context_class_ref(_level),
                getattr(self, '_verify_spid_{}'.format(index + 1))
            )

    def _verify_spid_1(self, verify=False, **kwargs):
        self.app.logger.debug('spid level 1 - verifica ({})'.format(verify))
        return self._verify_spid(1, verify, **kwargs)

    def _verify_spid_2(self, verify=False, **kwargs):
        self.app.logger.debug('spid level 2 - verifica ({})'.format(verify))
        return self._verify_spid(2, verify, **kwargs)

    def _verify_spid_3(self, verify=False, **kwargs):
        self.app.logger.debug('spid level 3 - verifica ({})'.format(verify))
        return self._verify_spid(3, verify, **kwargs)

    def _verify_spid(self, level=1, verify=False, **kwargs):
        """
        :param level: integer, SPID level
        :param verify: boolean, if True verify
            spid extra challenge (otp etc.), if False prepare the challenge
        :param kwargs: dictionary, extra arguments
        """
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

    def _check_spid_restrictions(self, msg, action, binding, **kwargs):
        parsed_msg, errors = self.spid_parser.parse(
            msg.message, action, binding, **kwargs
        )
        self.app.logger.debug('parsed authn_request: {}'.format(parsed_msg))
        return parsed_msg, errors

    def _store_request(self, authnreq):
        """
        Store authnrequest in a dictionary

        :param authnreq: authentication request string
        """
        self.app.logger.debug('store_request: {}'.format(authnreq))
        key = sha1(authnreq.xmlstr).hexdigest()
        # store the AuthnRequest
        self.ticket[key] = authnreq
        return key

    def _handle_errors(self, errors, xmlstr):
        _escaped_xml = escape(prettify_xml(xmlstr.decode()))
        rendered_error_response = render_template_string(
            spid_error_table,
            **{
                'lines': _escaped_xml.splitlines(),
                'errors': errors
                }
            )
        return rendered_error_response

    def _verify_redirect(self, saml_msg, issuer_name):
        """
        Verify Http-Redirect signature

        :param saml_msg: request parameters
        :param issuer_name: issuer name (Service Provider)
        """
        if "SigAlg" in saml_msg and "Signature" in saml_msg:
            # Signed request
            self.app.logger.debug('Messaggio SAML firmato.')
            _sig_alg = saml_msg['SigAlg']
            if _sig_alg not in ALLOWED_SIG_ALGS:
                self._raise_error(
                    'L\'Algoritmo {} non è supportato.'.format(_sig_alg)
                )
            try:
                _certs = self.server.metadata.certs(
                    issuer_name,
                    "any",
                    "signing"
                )
            except KeyError:
                self._raise_error(
                    'entity ID {} non registrato, impossibile ricavare'\
                    ' un certificato valido.'.format(issuer_name)
                )
            verified_ok = False
            for cert in _certs:
                self.app.logger.debug(
                    'security backend: {}'.format(
                        self.server.sec.sec_backend.__class__.__name__
                    )
                )
                # Check signature
                if verify_redirect_signature(
                    saml_msg,
                    self.server.sec.sec_backend,
                    cert
                ):
                    verified_ok = True
                    break
            if not verified_ok:
                self._raise_error(
                    'Verifica della firma del messaggio fallita.'
                )
        else:
            self._raise_error('Messaggio SAML non firmato.')

    def _parse_message(self, action='login'):
        """
        Parse an AuthnRequest or a LogoutRequest using pysaml2 API

        :param saml_msg: request parameters
        :param method: request method
        :param action: type of request
        """
        method = request.method

        if method == 'GET':
            _binding = BINDING_HTTP_REDIRECT
            saml_msg = self.unpack_args(request.args)
        elif method == 'POST':
            _binding = BINDING_HTTP_POST
            saml_msg = self.unpack_args(request.form)
        else:
            self._raise_error(
                'I metodi consentiti sono'\
                ' GET (Http-Redirect) o POST (Http-Post)'
            )
        if 'SAMLRequest' not in saml_msg:
            self._raise_error('Parametro SAMLRequest assente.')
        if action == 'login':
            _func = 'parse_authn_request'
        elif action == 'logout':
            _func = 'parse_logout_request'
        try:
            req_info = getattr(
                self.server, _func
                )(
                    saml_msg['SAMLRequest'], _binding
                )
        except IncorrectlySigned as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'Messaggio corrotto o non firmato correttamente.'
            )
        return req_info, _binding

    def single_sign_on_service(self):
        """
        Process Http-Redirect or Http-POST request

        :param request: Flask request object
        """
        # Unpack parameters
        saml_msg = self.unpack_args(request.args)
        try:
            req_info, binding = self._parse_message(action='login')
            authn_req = req_info.message
            self.app.logger.debug(
                'AuthnRequest: \n{}'.format(prettify_xml(str(authn_req)))
            )
            extra = {}
            sp_id = authn_req.issuer.text
            issuer_name = authn_req.issuer.text
            if issuer_name and issuer_name not in self.server.metadata.service_providers():
                raise UnknownSystemEntity
            # TODO: refactor a bit fetching this kind of data from pysaml2
            atcss = []
            for k, _md in self.server.metadata.items():
                if k == sp_id:
                    _srvs = _md.get('spsso_descriptor', [])
                    for _srv in _srvs:
                        for _acs in _srv.get(
                            'attribute_consuming_service', []
                        ):
                            atcss.append(_acs)
            try:
                ascss = self.server.metadata.assertion_consumer_service(sp_id)
            except UnknownSystemEntity as err:
                ascss = []
            except UnsupportedBinding as err:
                ascss = []
            atcss_indexes = [str(el.get('index')) for el in atcss]
            ascss_indexes = [str(el.get('index')) for el in ascss]
            extra['attribute_consuming_service_indexes'] = atcss_indexes
            extra['assertion_consumer_service_indexes'] = ascss_indexes
            extra['receivers'] = req_info.receiver_addrs
            _, errors = self._check_spid_restrictions(
                req_info, 'login', binding, **extra
            )
        except UnknownBinding as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'Binding non supportato. Formati supportati ({}, {})'.format(
                    BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
                )
            )
        except UnknownSystemEntity as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'entity ID {} non registrato.'.format(issuer_name)
            )
        except IncorrectlySigned as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'Messaggio corrotto o non firmato correttamente.'.format(
                    issuer_name
                )
            )

        if errors:
            return self._handle_errors(errors, req_info.xmlstr)

        if not req_info:
            self._raise_error('Processo di parsing del messaggio fallito.')

        # Check if it is signed
        if binding == BINDING_HTTP_REDIRECT:
            self._verify_redirect(saml_msg, issuer_name)
        # Perform login
        key = self._store_request(req_info)
        relay_state = saml_msg.get('RelayState', '')
        session['request_key'] = key
        session['relay_state'] = relay_state
        return redirect(url_for('login'))

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
        acs_index = req.message.assertion_consumer_service_index
        if acs_index is not None:
            acss = self.server.metadata.assertion_consumer_service(
                sp_id, req.message.protocol_binding
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
            destination = req.message.assertion_consumer_service_url
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
            message = authn_request.message
            sp_id = message.issuer.text
            destination = self.get_destination(authn_request, sp_id)
            authn_context = message.requested_authn_context
            spid_level = authn_context.authn_context_class_ref[0].text
            authn_info = self.authn_broker.pick(authn_context)
            callback, reference = authn_info[0]
            if request.method == 'GET':
                # inject extra data in form login based on spid level
                extra_challenge = callback(**{'key': key})
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
                verified = callback(
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
                        AUTHN = {
                            "class_ref": spid_level,
                            "authn_auth": spid_level
                        }
                        self.app.logger.debug(
                            'Unfiltered data: {}'.format(identity)
                        )
                        atcs_idx = message.attribute_consuming_service_index
                        self.app.logger.debug(
                            'attribute_consuming_service_index: {}'.format(
                                atcs_idx
                            )
                        )
                        if atcs_idx:
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
                        _data = dict(
                            identity=identity, userid=user_id,
                            in_response_to=message.id,
                            destination=destination,
                            sp_entity_id=sp_id,
                            authn=AUTHN, issuer=self.server.config.entityid,
                            sign_alg=SIGN_ALG,
                            digest_alg=DIGEST_ALG,
                            sign_assertion=True,
                            release_policy=SpidPolicy(
                                restrictions={
                                    'default': {
                                        'name_form': NAME_FORMAT_BASIC,
                                    }
                                },
                                index=atcs_idx
                            )
                        )
                        response = self.server.create_authn_response(
                            **_data
                        )
                        self.app.logger.debug(
                            'Response: \n{}'.format(response)
                        )
                        http_args = self.server.apply_binding(
                            BINDING_HTTP_POST,
                            response,
                            destination,
                            response=True,
                            sign=True,
                            relay_state=relay_state
                        )
                        # Setup confirmation page data
                        self.responses[key] = http_args['data']
                        rendered_response = render_template(
                            'confirm.html',
                            **{
                                'destination_service': sp_id,
                                'lines':  escape(
                                    prettify_xml(response)
                                ).splitlines(),
                                'attrs': identity.keys(),
                                'action': '/continue-response',
                                'request_key': key
                            }
                        )
                        return rendered_response, 200
            elif 'delete' in request.form:
                error_response = self.server.create_error_response(
                    in_response_to=authn_request.message.id,
                    destination=destination,
                    info=get_spid_error(
                        AUTH_NO_CONSENT
                    )
                )
                self.app.logger.debug(
                    'Error response: \n{}'.format(
                        prettify_xml(str(error_response))
                    )
                )
                http_args = self.server.apply_binding(
                    BINDING_HTTP_POST,
                    error_response,
                    destination,
                    response=True,
                    sign=True,
                    relay_state=relay_state
                )
                del self.ticket[key]
                return http_args['data'], 200
        return render_template('403.html'), 403

    def continue_response(self):
        key = request.form['request_key']
        if key and key in self.responses and key in self.responses:
            _response = self.responses.pop(key)
            auth_req = self.ticket.pop(key)
            if 'confirm' in request.form:
                return _response, 200
            elif 'delete' in request.form:
                destination = self.get_destination(
                    auth_req, auth_req.message.issuer.text
                )
                error_response = self.server.create_error_response(
                    in_response_to=auth_req.message.id,
                    destination=destination,
                    info=get_spid_error(
                        AUTH_NO_CONSENT
                    )
                )
                self.app.logger.debug(
                    'Error response: \n{}'.format(
                        prettify_xml(str(error_response))
                    )
                )
                http_args = self.server.apply_binding(
                    BINDING_HTTP_POST,
                    error_response,
                    destination,
                    response=True,
                    sign=True,
                )
                return http_args['data'], 200
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
        saml_msg = self.unpack_args(request.args)
        try:
            req_info, _binding = self._parse_message(action='logout')
            msg = req_info.message
            self.app.logger.debug(
                'LogoutRequest: \n{}'.format(
                    prettify_xml(str(msg))
                )
            )
            issuer_name = req_info.issuer.text
            extra = {}
            extra['receivers'] = req_info.receiver_addrs
            _, errors = self._check_spid_restrictions(
                req_info, 'logout', _binding, **extra
            )
        except UnknownBinding as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'Binding non supportato. Formati supportati ({}, {})'.format(
                    BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
                )
            )
        except UnknownSystemEntity as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'entity ID {} non registrato.'.format(issuer_name)
            )
        except IncorrectlySigned as err:
            self.app.logger.debug(str(err))
            self._raise_error(
                'Messaggio corrotto o non firmato correttamente.'
            )

        if errors:
            return self._handle_errors(errors, req_info.xmlstr)

        # Check if it is signed
        if _binding == BINDING_HTTP_REDIRECT:
            self._verify_redirect(saml_msg, issuer_name)
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
        _signing = True if response_binding == BINDING_HTTP_POST else False
        self.app.logger.debug(
            'Signature inside response: \n{}'.format(
                _signing
            )
        )
        response = self.server.create_logout_response(
            msg, [response_binding],
            sign_alg=SIGN_ALG,
            digest_alg=DIGEST_ALG,
            sign=_signing
        )
        self.app.logger.debug('Response: \n{}'.format(response))
        binding, destination = self.server.pick_binding(
            "single_logout_service",
            [response_binding], "spsso",
            req_info
        )
        self.app.logger.debug('Destination {}'.format(destination))
        if response_binding == BINDING_HTTP_POST:
            _sign = False
            extra = {}
        else:
            _sign = True
            extra = {'sigalg': SIGN_ALG}

        relay_state = saml_msg.get('RelayState', '')
        http_args = self.server.apply_binding(
            binding,
            "%s" % response, destination, response=True,
            sign=_sign, relay_state=relay_state, **extra
        )
        if response_binding == BINDING_HTTP_POST:
            self.app.logger.debug('Form post {}'.format(http_args['data']))
            return http_args['data'], 200
        elif response_binding == BINDING_HTTP_REDIRECT:
            headers = dict(http_args['headers'])
            self.app.logger.debug('Headers {}'.format(headers))
            location = headers.get('Location')
            self.app.logger.debug('Location {}'.format(location))
            if location:
                return redirect(location)
        abort(400)

    def metadata(self):
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
