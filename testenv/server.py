# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import random
import string
from collections import namedtuple
from datetime import datetime
from hashlib import sha1
from logging.handlers import RotatingFileHandler

from flask import Response, abort, escape, redirect, render_template, request, session, url_for

from testenv import config, spmetadata
from testenv.crypto import HTTPPostSignatureVerifier, HTTPRedirectSignatureVerifier, sign_http_post, sign_http_redirect
from testenv.exceptions import (
    DeserializationError, MetadataLoadError, NoCertificateError, RequestParserError, SignatureVerificationError,
    UnknownEntityIDError,
)
from testenv.parser import (
    HTTPPostRequestParser, HTTPRedirectRequestParser, get_http_post_request_deserializer,
    get_http_redirect_request_deserializer,
)
from testenv.saml import create_error_response, create_idp_metadata, create_logout_response, create_response
from testenv.settings import (
    AUTH_NO_CONSENT, BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, CHALLENGES_TIMEOUT, SPID_ATTRIBUTES, SPID_LEVELS,
    STATUS_SUCCESS,
)
from testenv.users import JsonUserManager
from testenv.utils import Key, Slo, Sso, get_spid_error

# FIXME: move to a the parser.py module after metadata refactoring
SPIDRequest = namedtuple('SPIDRequest', ['data', 'saml_tree'])


def from_session(key):
    return session[key] if key in session else None


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
    _spid_attributes = SPID_ATTRIBUTES.copy()
    # digitalAddress => PEC
    challenges_timeout = CHALLENGES_TIMEOUT

    def __init__(self, app, conf=None, registry=None, *args, **kwargs):
        """
        :param app: Flask instance
        :param conf: config.Config instance
        :param args:
        :param kwargs:
        """
        # bind Flask app
        self.app = app
        self.user_manager = JsonUserManager()
        # setup
        self._config = conf or config.params
        self._registry = registry or spmetadata.registry
        self.app.secret_key = 'sosecret'
        handler = RotatingFileHandler(
            'spid.log', maxBytes=500000, backupCount=1
        )
        self.app.logger.addHandler(handler)
        self._prepare_server()

    @property
    def _mode(self):
        return 'https' if self._config.https else 'http'

    def _setup_app_routes(self):
        """
        Setup Flask routes
        """
        # Setup SSO and SLO endpoints
        endpoints = self._config.endpoints
        if endpoints:
            for ep_type in self._endpoint_types:
                _url = endpoints.get(ep_type)
                if _url:
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
        # FIXME: remove after pysaml2 drop
        # from saml2.config import Config as Saml2Config
        # self.idp_config = Saml2Config()
        # self.idp_config.load(cnf=self._config.pysaml2compat)
        # self.server = Server(config=self.idp_config)
        #
        self._setup_app_routes()

    def _verify_spid(self, level, verify=False, **kwargs):
        """
        :param level: integer, SPID level
        :param verify: boolean, if True verify
            spid extra challenge (otp etc.), if False prepare the challenge
        :param kwargs: dictionary, extra arguments
        """
        level = self._spid_levels.index(level)
        self.app.logger.debug(
            'spid level {} - verifica ({})'.format(level, verify))
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
                _is_expired = total_seconds > self.challenges_timeout
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
            request_data, action)
        saml_tree = deserializer.deserialize()
        certs = self._get_certificates_by_issuer(saml_tree.issuer.text)
        if not certs:
            raise NoCertificateError
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
        deserializer = get_http_post_request_deserializer(request_data, action)
        saml_tree = deserializer.deserialize()
        certs = self._get_certificates_by_issuer(saml_tree.issuer.text)
        if not certs:
            raise NoCertificateError
        for cert in certs:
            HTTPPostSignatureVerifier(cert, request_data).verify()
        return SPIDRequest(request_data, saml_tree)

    def _get_certificates_by_issuer(self, issuer):
        try:
            return self._registry.get(issuer).certs()
        except KeyError:
            self._raise_error(
                'entity ID {} non registrato, impossibile ricavare'
                ' un certificato valido.'.format(issuer)
            )
        except NoCertificateError:
            self._raise_error(
                'Errore, il metadata associato al Service provider non'
                ' non è provvisto di certificati validi'.format(issuer)
            )

    def single_sign_on_service(self):
        """
        Process Http-Redirect or Http-POST request

        :param request: Flask request object
        """
        try:
            spid_request = self._parse_message(action='login')
            self.app.logger.debug(
                'AuthnRequest: \n{}'.format(spid_request.data.saml_request)
            )
            # Perform login
            key = self._store_request(spid_request.saml_tree)
            session['request_key'] = key
            session['relay_state'] = spid_request.data.relay_state or ''
            return redirect(url_for('login'))
        except RequestParserError as err:
            self._raise_error(err.args[0])
        except SignatureVerificationError as err:
            self._raise_error(err.args[0])
        except UnknownEntityIDError as err:
            self._raise_error(err.args[0])
        except DeserializationError as err:
            return self._handle_errors(err.initial_data, err.details)
        except MetadataLoadError as err:
            self._raise_error('Metadata non disponibile: {}'.format(err.args[0]))

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
                'sp_list': self._registry.service_providers,
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
            if 'fiscalNumber' in extra:
                extra[
                    'fiscalNumber'] = 'TINIT-{}'.format(extra['fiscalNumber'])
            self.user_manager.add(username, password, sp, extra.copy())
        return redirect(url_for('users'))

    def index(self):
        rendered_form = render_template(
            "home.html",
            **{
                'sp_list': [
                    {
                        "name": sp, "spId": sp
                    } for sp in self._registry.service_providers
                ],
            }
        )
        return rendered_form, 200

    def get_destination(self, req, sp_id):
        destination = None
        acs_index = getattr(req, 'assertion_consumer_service_index', None)
        protocol_binding = getattr(req, 'protocol_binding', None)
        if acs_index is not None:
            acss = self._registry.get(
                sp_id).assertion_consumer_service(index=acs_index)
            if acss:
                destination = acss[0].get('Location')
            self.app.logger.debug(
                'AssertionConsumerServiceIndex Location: {}'.format(
                    destination
                )
            )
        if destination is None:
            destination = getattr(req, 'assertion_consumer_service_url', None)
            if destination is not None and protocol_binding is not None:
                self.app.logger.debug(
                    'AssertionConsumerServiceURL: {}'.format(
                        destination
                    )
                )
        return destination

    def _attribute_type(self, attribute_name):
        if attribute_name in self._spid_main_fields:
            _type = self._spid_attributes['primary'][attribute_name]
        else:
            _type = self._spid_attributes['secondary'][attribute_name]
        return _type

    def login(self):
        """
        Login endpoint (verify user credentials)
        """

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
                extra_challenge = self._verify_spid(
                    level=spid_level, **{'key': key})
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
                        self.app.logger.debug(
                            'Unfiltered data: {}'.format(identity)
                        )
                        atcs_idx = getattr(
                            authn_request, 'attribute_consuming_service_index', None)
                        self.app.logger.debug(
                            'AttributeConsumingServiceIndex: {}'.format(
                                atcs_idx
                            )
                        )
                        sp_metadata = self._registry.get(sp_id)
                        required = []
                        optional = []
                        if atcs_idx and sp_metadata:
                            attrs = sp_metadata.attributes(atcs_idx)
                            required = [el for el in attrs.get('required')]
                            optional = [el for el in attrs.get('optional')]

                        for attr_name, val in identity.items():
                            _type = self._attribute_type(attr_name)
                            identity[attr_name] = (_type, val)

                        _identity = {}
                        # TODO: refactor a bit the following snippet
                        for _key in required:
                            try:
                                _identity[_key] = identity[_key]
                            except KeyError:
                                _identity[_key] = (
                                    '', self._attribute_type(_key))
                        for _key in optional:
                            try:
                                _identity[_key] = identity[_key]
                            except KeyError:
                                _identity[_key] = (
                                    '', self._attribute_type(_key))

                        self.app.logger.debug(
                            'Filtered data: {}'.format(_identity)
                        )

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
                                        'name_qualifier': self._config.entity_id,
                                    },
                                    'text': self._config.entity_id
                                },
                                'name_id': {
                                    'attrs': {
                                        'name_qualifier': self._config.entity_id,
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
                            _identity.copy()
                        ).to_xml()
                        response = sign_http_post(
                            response_xmlstr,
                            self._config.idp_key,
                            self._config.idp_certificate,
                        )
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
                                'attrs': _identity.keys(),
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
                                'name_qualifier': self._config.entity_id,
                            },
                            'text': self._config.entity_id
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
                response = sign_http_post(
                    response,
                    self._config.idp_key,
                    self._config.idp_certificate,
                )
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
        relay_state = from_session('relay_state')
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
                                'in_response_to': auth_req.id,
                                'destination': destination
                            }
                        },
                        'issuer': {
                            'attrs': {
                                'name_qualifier': 'something',
                            },
                            'text': self._config.entity_id
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
                response = sign_http_post(
                    response,
                    self._config.idp_key,
                    self._config.idp_certificate,
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
                return rendered_template, 200
        return render_template('403.html'), 403

    def _sp_single_logout_service(self, issuer_name):
        _slo = None
        try:
            _slo = self._registry.get(issuer_name).single_logout_services[0]
        except Exception:
            pass
        return _slo

    def single_logout_service(self):
        """
        SLO endpoint
        """

        self.app.logger.debug("req: '%s'", request)
        try:
            spid_request = self._parse_message(action='logout')
            issuer_name = spid_request.saml_tree.issuer.text
            _slo = self._sp_single_logout_service(issuer_name)
            if _slo is None:
                self._raise_error(
                    'Impossibile trovare un servizio di'
                    ' Single Logout per il service provider {}'.format(
                        issuer_name
                    )
                )
            response_binding = _slo.get('Binding')
            self.app.logger.debug(
                'Response binding: \n{}'.format(
                    response_binding
                )
            )
            destination = _slo.get('Location')
            response = create_logout_response(
                {
                    'logout_response': {
                        'attrs': {
                            'in_response_to': spid_request.saml_tree.id,
                            'destination': destination
                        }
                    },
                    'issuer': {
                        'attrs': {
                            'name_qualifier': 'something',
                        },
                        'text': self._config.entity_id
                    }
                },
                {
                    'status_code': STATUS_SUCCESS
                }
            ).to_xml()
            relay_state = spid_request.data.relay_state or ''
            if response_binding == BINDING_HTTP_POST:
                response = sign_http_post(
                    response,
                    self._config.idp_key,
                    self._config.idp_certificate,
                    message=True, assertion=False
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
                return rendered_template, 200
            elif response_binding == BINDING_HTTP_REDIRECT:
                query_string = sign_http_redirect(
                    response,
                    self._config.idp_key,
                    relay_state,
                )
                location = '{}?{}'.format(destination, query_string)
                if location:
                    return redirect(location)
        except RequestParserError as err:
            self._raise_error(err.args[0])
        except SignatureVerificationError as err:
            self._raise_error(err.args[0])
        except UnknownEntityIDError as err:
            self._raise_error(err.args[0])
        except DeserializationError as err:
            return self._handle_errors(err.initial_data, err.details)
        except MetadataLoadError as err:
            self._raise_error(err.args[0])
        abort(400)

    def metadata(self):
        cert_file = self._config.idp_certificate_file_path
        with open(cert_file, 'r') as fp:
            cert = fp.readlines()[1:-1]
            cert = ''.join(cert)
        endpoints = self._config.endpoints
        sso = self._config.entity_id + endpoints.get('single_sign_on_service')
        slo = self._config.entity_id + endpoints.get('single_logout_service')
        sso_list = []
        slo_list = []
        sso_list.append(
            Sso(
                binding=BINDING_HTTP_POST,
                location=sso
            )
        )
        sso_list.append(
            Sso(
                binding=BINDING_HTTP_REDIRECT,
                location=sso
            )
        )
        slo_list.append(
            Slo(
                binding=BINDING_HTTP_POST,
                location=slo
            )
        )
        slo_list.append(
            Slo(
                binding=BINDING_HTTP_REDIRECT,
                location=slo
            )
        )
        metadata = create_idp_metadata(
            entity_id=self._config.entity_id,
            want_authn_requests_signed='true',
            keys=[Key(use='signing', value=cert)],
            single_sign_on_services=sso_list,
            single_logout_services=slo_list
        ).to_xml()
        return Response(metadata, mimetype='text/xml')

    @property
    def _wsgiconf(self):
        _cnf = {
            'host': self._config.host,
            'port': self._config.port,
            'debug': self._config.debug,
        }
        if self._config.https:
            key = self._config.https_key_file_path
            cert = self._config.https_certificate_file_path
            _cnf['ssl_context'] = (cert, key,)
        return _cnf

    def start(self):
        """
        Start the server instance
        """
        self.app.run(
            **self._wsgiconf
        )
