# -*- coding: utf-8 -*-
import argparse
import json
import logging
import os.path
import random
import string
from datetime import datetime
from hashlib import sha1, sha512
from logging.handlers import RotatingFileHandler

import saml2.xmldsig as ds
import yaml
from flask import Flask, Response, abort, redirect, request, session, url_for
from passlib.hash import sha512_crypt
from saml2 import (BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_URI,
                   NAMESPACE)
from saml2.assertion import Assertion
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from saml2.config import Config as Saml2Config
from saml2.metadata import create_metadata_string
from saml2.saml import NAME_FORMAT_BASIC, NAMEID_FORMAT_TRANSIENT
from saml2.server import Server
from saml2.sigver import verify_redirect_signature

try:
    FileNotFoundError
except NameError:
    #py2
    FileNotFoundError = IOError

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'


SIGN_ALG = ds.SIG_RSA_SHA1
DIGEST_ALG = ds.DIGEST_SHA1

error_table = '''
<html>
    <head>
    </head>
    <body>
        <table border=1>
            <thead>
                <tr>
                    <th>Errore</th>
                    <th>Dettagli</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>{}</td>
                    <td>{}</td>
                </tr>
            </tbody>
        </table>
    </body>
</html>
'''

FORM_LOGIN = '''
<form name="login" method="post" action="{}">
   <input type="hidden" name="request_key" value="{}" />
   <input type="hidden" name="relay_state" value="{}" />
   <span>Username</span> <input type="text" name="username" /><br>
   <span>Password</span> <input type="password" name="password" /><br>
   {}
   <input type="submit"/>
</form>
'''

FORM_ADD_USER = '''
<form name="add_user" method="post" action="{}">
   <b>Credentials</b><br>
   <span>Username</span> <input type="text" name="username" /><br>
   <span>Password</span> <input type="password" name="password" /><br>
   <span>Service provider id</span> <input type="text" name="service_provider" /><br>
   {}
   <input type="submit"/>
</form>
'''

CONFIRM_PAGE = '''
<html>
    <head>
    </head>
    <body>
        Vuoi trasmettere i seguenti attributi?
        <table border=1>
            <thead>
                <tr>
                    <th>attributo</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
        <form name="make_response" method="post" action="{}">
            <input type="hidden" name="request_key" value="{}" />
            <input type="submit"/>
        </form>
    </body>
</html>
'''


class Attr(object):

    MANDATORY_ERROR = 'L\'attributo {} è obbligatorio'
    DEFAULT_VALUE_ERROR = '{} è diverso dal valore di riferimento {}'

    def __init__(self, name, required=True, default=None, *args, **kwargs):
        self._name = name
        self._required = required
        self._errors = {}
        self._default = default

    def validate(self, value=None):
        if self._required and value is None:
            self._errors['required_error'] = self.MANDATORY_ERROR.format(self._name)
        if self._default is not None and self._default != value:
            self._errors['value_error'] = self.DEFAULT_VALUE_ERROR.format(value, self._default)
        return {
            'value': value if not self._errors else None,
            'errors': self._errors
        }


class Elem(object):

    MANDATORY_ERROR = 'L\'attributo {} è obbligatorio'

    def __init__(self, name, required=True, attributes=[], children=[], *args, **kwargs):
        self._name = name
        self._required = required
        self._attributes = attributes
        self._children = children

    def validate(self, data):
        res = { 'attrs': {}, 'children': {}, 'errors': {} }
        if self._required and data is None:
            res['errors']['required_error'] = self.MANDATORY_ERROR.format(self._name)
        if data:
            for attribute in self._attributes:
                res['attrs'][attribute._name] = attribute.validate(getattr(data, attribute._name))
            for child in self._children:
                res['children'][child._name] = child.validate(getattr(data, child._name))
        return res


class SpidParser(object):

    def __init__(self, *args, **kwargs):
        self.schema = None
        self.errors = 0

    def get_schema(self, binding):
        required_signature = False
        if binding == BINDING_HTTP_POST:
            required_signature = True
        elif binding == BINDING_HTTP_REDIRECT:
            required_signature = False

        _schema = Elem(
            name='auth_request',
            attributes=[
                Attr('id'),
                Attr('version', default='2.0'),
                Attr('issue_instant'),
                Attr('destination'),
                Attr('force_authn', required=False),
                Attr('attribute_consuming_service_index', required=False),
                Attr('assertion_consumer_service_url', required=False),
                Attr('protocol_binding', default='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', required=False)
            ],
            children=[
                Elem(
                    'subject',
                    required=False,
                    attributes=[
                        Attr('format', default='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'),
                        Attr('name_qualifier')
                    ]
                ),
                Elem(
                    'issuer',
                    attributes=[
                        Attr('format', default='urn:oasis:names:tc:SAML:2.0:nameid-format:entity'),
                        Attr('name_qualifier')
                    ]
                ),
                Elem(
                    'name_id_policy',
                    attributes=[
                        Attr('allow_create', required=False, default='true'),
                        Attr('format', default='urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
                    ]
                ),
                Elem(
                    'conditions',
                    required=False,
                    attributes=[
                        Attr('not_before'),
                        Attr('Not_on_or_after')
                    ]
                ),
                Elem(
                    'requested_authn_context',
                    attributes=[
                        Attr('comparison'),
                    ],
                    children=[
                        # Elem(
                        #     'authn_context_class_ref',
                        #     attributes=[
                        #         Attr('text')
                        #     ]
                        # )
                    ]
                ),
                Elem(
                    'signature',
                    required=required_signature,
                ),
            ]
        )
        return _schema

    def parse(self, obj, binding, schema=None):
        res = {}
        _schema = self.get_schema(binding) if schema is None else schema
        return _schema.validate(obj)


class BadConfiguration(Exception):
    pass


class AbstractUserManager(object):
    """
    Base User manager class to handling user objects
    """
    def get(self, uid, pwd, sp_id):
        raise NotImplementedError

    def add(self, uid, pwd, sp_id, extra={}):
        raise NotImplementedError


class JsonUserManager(AbstractUserManager):
    """
    User manager class to handling json user objects
    """
    FILE_NAME = 'users.json'

    def _load(self):
        try:
            with open(self.FILE_NAME, 'r') as fp:
                self.users = json.loads(fp.read())
        except FileNotFoundError:
            self.users = {}
            self._save()

    def _save(self):
        with open(self.FILE_NAME, 'w') as fp:
            json.dump(self.users, fp, indent=4)

    def __init__(self, *args, **kwargs):
        self._load()

    def get(self, uid, pwd, sp_id):
        for user, _attrs in self.users.items():
            if sha512_crypt.verify(pwd, _attrs['pwd']) and _attrs['sp'] == sp_id:
                return user, self.users[user]
        return None, None

    def add(self, uid, pwd, sp_id, extra={}):
        if uid not in self.users:
            self.users[uid] = {
                'pwd': sha512_crypt.encrypt(pwd),
                'sp': sp_id,
                'attrs': extra
            }
        self._save()



class IdpServer(object):

    ticket = {}
    responses = {}
    challenges = {}
    _binding_mapping = {
        'http-redirect': BINDING_HTTP_REDIRECT,
        'http-post': BINDING_HTTP_POST
    }
    _endpoint_types = ['single_sign_on_service', 'single_logout_service']
    _spid_levels = [
        'https://www.spid.gov.it/SpidL1',
        'https://www.spid.gov.it/SpidL2',
        'https://www.spid.gov.it/SpidL3'
    ]
    _spid_attributes = {
        'primary': {
            'spidCode' : 'xs:string',
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
            'digitalAddress': 'xs:string' # PEC
        }
    }
    CHALLENGES_TIMEOUT = 30 # seconds
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
        self.user_manager = JsonUserManager()
        # setup
        self._config = config
        self.app.secret_key = 'sosecret'
        handler = RotatingFileHandler('spid.log', maxBytes=500000, backupCount=1)
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
        existing_key = os.path.isfile(key_file_path) if key_file_path else None
        existing_cert = os.path.isfile(cert_file_path) if cert_file_path else None
        if not existing_key:
            raise BadConfiguration('Chiave privata dell\'IdP di test non trovata: {} non trovato'.format(key_file_path))
        if not existing_cert:
            raise BadConfiguration('Certificato dell\'IdP di test non trovato: {} non trovato'.format(cert_file_path))
        self.entity_id = self._config.get('hostname')
        if not self.entity_id:
            self.entity_id = self._config.get('host')
        self.entity_id = '{}://{}'.format(self._mode, self.entity_id)
        port = self._config.get('port')
        if port:
            self.entity_id = '{}:{}'.format(self.entity_id, port)
        idp_conf = {
            "entityid": self.entity_id,
            "description": "Spid Test IdP",
            "service": {
                "idp": {
                    "name": "Spid Testenv",
                    "endpoints": {
                        "single_sign_on_service": [
                        ],
                        "single_logout_service": [
                        ],
                    },
                    "policy": {
                        "default": {
                            "name_form": NAME_FORMAT_BASIC,
                        },
                    },
                    "name_id_format": [
                        NAMEID_FORMAT_TRANSIENT,
                    ]
                },
            },
            "debug": 1,
            "key_file": self._config.get('key_file'),
            "cert_file": self._config.get('cert_file'),
            "metadata": metadata,
            "organization": {
                "display_name": "Spid testenv",
                "name": "Spid testenv",
                "url": "http://www.example.com",
            },
            "contact_person": [
                {
                    "contact_type": "technical",
                    "given_name": "support",
                    "sur_name": "support",
                    "email_address": "technical@example.com"
                },
            ],

            "logger": {
                "rotating": {
                    "filename": "idp.log",
                    "maxBytes": 500000,
                    "backupCount": 1,
                },
                "loglevel": "debug",
            }
        }
        # setup services url
        for _service_type in self._endpoint_types:
            endpoint = self._config['endpoints'][_service_type]
            idp_conf['service']['idp']['endpoints'][_service_type].append(
                ('{}{}'.format(self.entity_id, endpoint), BINDING_HTTP_REDIRECT)
            )
            idp_conf['service']['idp']['endpoints'][_service_type].append(
                ('{}{}'.format(self.entity_id, endpoint), BINDING_HTTP_POST)
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
                        raise BadConfiguration('Errore nella configurazione delle url, i path devono essere relativi ed iniziare con "/" (slash) - url {}'.format(_url)
                    )
                    for _binding in self._binding_mapping.keys():
                        self.app.add_url_rule(_url, '{}_{}'.format(ep_type, _binding), getattr(self, ep_type), methods=['GET',])
        self.app.add_url_rule('/login', 'login', self.login, methods=['POST', 'GET',])
        # Endpoint for user add action
        self.app.add_url_rule('/add-user', 'add_user', self.add_user, methods=['GET', 'POST',])
        self.app.add_url_rule('/continue-response', 'continue_response', self.continue_response, methods=['POST',])
        self.app.add_url_rule('/metadata', 'metadata', self.metadata, methods=['POST', 'GET'])

    def _prepare_server(self):
        """
        Setup server
        """
        self.idp_config = Saml2Config()
        self.BASE = '{}://{}:{}'.format(self._mode, self._config.get('host'), self._config.get('port'))
        if 'entityid' not in self._config:
            # as fallback for entityid use host:port string
            self._config['entityid'] = self.BASE
        self.idp_config.load(cnf=self._idp_config())
        self.server = Server(config=self.idp_config)
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
        :param verify: boolean, if True verify spid extra challenge (otp etc.), if False prepare the challenge
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
                total_seconds = (datetime.now() - self.challenges[key][1]).total_seconds()
                # Check that opt value is equal and not expired
                if self.challenges[key][0] != otp or total_seconds > self.CHALLENGES_TIMEOUT:
                    del self.challenges[key]
                    return False
            return True
        else:
            # Prepare the challenge
            if level == 2:
                # spid level 2
                # very simple otp implementation, while opt is a random 6 digits string
                # with a lifetime setup in the server instance
                key = kwargs.get('key')
                otp = ''.join(random.choice(string.digits) for _ in range(6))
                self.challenges[key] = [otp, datetime.now()]
                extra_challenge = '<span>Otp ({})</span><input type="text" name="otp" />'.format(otp)
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
                error_table.format(msg, extra),
                200
            )
        )

    def _check_spid_restrictions(self, msg, binding):
        errors = []
        parsed_msg = SpidParser().parse(msg.message, binding)
        self.app.logger.debug('parsed authn_request: {}'.format(parsed_msg))
        return errors

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

    def _handle_errors(self, errors):
        # TODO: handle errors
        pass

    def single_sign_on_service(self):
        """
        Process Http-Redirect or Http-POST request

        :param request: Flask request object
        """
        self.app.logger.info("Http-Redirect")
        # Unpack parameters
        saml_msg = self.unpack_args(request.args)
        try:
            _key = session['request_key']
            req_info = self.ticket[_key]
        except KeyError as e:
            try:
                binding = self._get_binding('single_sign_on_service', request)
                # Parse AuthnRequest
                req_info = self.server.parse_authn_request(
                    saml_msg["SAMLRequest"],
                    binding
                )
                authn_req = req_info.message
                errors = self._check_spid_restrictions(req_info, binding)
            except KeyError as err:
                self.app.logger.debug(str(err))
                self._raise_error('Parametro SAMLRequest assente.')

            if errors:
                return self._handle_errors(errors)

            if not req_info:
                self._raise_error('Processo di parsing del messaggio fallito.')

            self.app.logger.debug('AuthnRequest: {}'.format(authn_req))
            # Check if it is signed
            if "SigAlg" in saml_msg and "Signature" in saml_msg:
                # Signed request
                self.app.logger.debug('Messaggio SAML firmato.')
                issuer_name = authn_req.issuer.text
                try:
                    _certs = self.server.metadata.certs(
                        issuer_name,
                        "any",
                        "signing"
                    )
                except KeyError:
                    self._raise_error('entity ID {} non registrato, impossibile ricavare un certificato valido.'.format(issuer_name))
                verified_ok = False
                for cert in _certs:
                    self.app.logger.debug(
                        'security backend: {}'.format(self.server.sec.sec_backend.__class__.__name__)
                    )
                    # Check signature
                    if verify_redirect_signature(saml_msg, self.server.sec.sec_backend,
                                                    cert):
                        verified_ok = True
                        break
                if not verified_ok:
                    self._raise_error('Verifica della firma del messaggio fallita.')
            else:
                self._raise_error('Messaggio SAML non firmato.')
            # Perform login
            key = self._store_request(req_info)
            relay_state = saml_msg.get('RelayState', '')
            session['request_key'] = key
            session['relay_state'] = relay_state
        return redirect(url_for('login'))

    def _get_binding(self, endpoint_type, request):
        try:
            endpoint = request.endpoint
            binding = endpoint.split('{}_'.format(endpoint_type))[1]
            return self._binding_mapping.get(binding)
        except IndexError:
            pass

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

    def add_user(self):
        """
        Add user endpoint
        """
        spid_main_fields = self._spid_main_fields
        spid_secondary_fields = self._spid_secondary_fields
        _fields = '<br><b>{}</b><br>'.format('Primary attributes')
        for _field_name in spid_main_fields:
            _fields = '{}<span>{}</span> <input type="text" name={} /><br>'.format(_fields, _field_name, _field_name)
        _fields = '{}<br><b>{}</b><br>'.format(_fields, 'Secondary attributes')
        for _field_name in spid_secondary_fields:
            _fields = '{}<span>{}</span> <input type="text" name={} /><br>'.format(_fields, _field_name, _field_name)
        if request.method == 'GET':
            return FORM_ADD_USER.format('/add-user', _fields), 200
        elif request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            sp = request.form.get('service_provider')
            if not username or not password or not sp:
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

    def login(self):
        """
        Login endpoint (verify user credentials)
        """
        key = session['request_key'] if 'request_key' in session else None
        relay_state = session['relay_state'] if 'relay_state' in session else ''
        self.app.logger.debug('Request key: {}'.format(key))
        if key and key in self.ticket:
            authn_request = self.ticket[key]
            sp_id = authn_request.message.issuer.text
            destination = authn_request.message.assertion_consumer_service_url
            spid_level = authn_request.message.requested_authn_context.authn_context_class_ref[0].text
            authn_info = self.authn_broker.pick(authn_request.message.requested_authn_context)
            callback, reference = authn_info[0]
            if request.method == 'GET':
                # inject extra data in form login based on spid level
                extra_challenge = callback(**{'key': key})
                return FORM_LOGIN.format(
                    url_for('login'),
                    key,
                    relay_state,
                    extra_challenge
                ), 200
            # verify optional challenge based on spid level
            verified = callback(verify=True, **{'key': key, 'data': request.form})
            if verified:
                # verify user credentials
                user_id, user = self.user_manager.get(
                    request.form['username'],
                    request.form['password'],
                    sp_id
                )
                if user_id is not None:
                    # setup response
                    attribute_statement_on_response = self._config.get('attribute_statement_on_response')
                    identity = user['attrs']
                    AUTHN = {
                        "class_ref": spid_level,
                        "authn_auth": spid_level
                    }
                    _data = dict(
                        identity=identity, userid=user_id,
                        in_response_to=authn_request.message.id,
                        destination=destination,
                        sp_entity_id=sp_id,
                        authn=AUTHN, issuer=self.server.config.entityid,
                        sign_alg=SIGN_ALG,
                        digest_alg=DIGEST_ALG,
                        sign_assertion=True
                    )
                    response = self.server.create_authn_response(
                        **_data
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
                    ast = Assertion(identity)
                    policy = self.server.config.getattr("policy", "idp")
                    ast.acs = self.server.config.getattr("attribute_converters", "idp")
                    res = ast.apply_policy(sp_id, policy, self.server.metadata)
                    attrs = res.keys()
                    attrs_list = ''
                    for _attr in attrs:
                        attrs_list = '{}<tr><td>{}</td></tr>'.format(attrs_list, _attr)
                    self.responses[key] = http_args['data']
                    return CONFIRM_PAGE.format(attrs_list, '/continue-response', key), 200
        abort(403)

    def continue_response(self):
        key = request.form['request_key']
        if key and key in self.ticket and key in self.responses:
            return self.responses[key], 200
        abort(403)

    def single_logout_service(self):
        """
        SLO endpoint

        :param binding: 'redirect' is http-redirect, 'post' is http-post binding
        """

        self.app.logger.debug("req: '%s'", request)
        saml_msg = self.unpack_args(request.args)
        _binding = self._get_binding('single_logout_service', request)
        req_info = self.server.parse_logout_request(saml_msg['SAMLRequest'], _binding)
        msg = req_info.message
        response = self.server.create_logout_response(
            msg, [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT],
            sign_alg=SIGN_ALG,
            digest_alg=DIGEST_ALG,
            sign=True
        )
        binding, destination = self.server.pick_binding(
            "single_logout_service",
            [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT], "spsso",
            req_info
        )
        http_args = self.server.apply_binding(
            binding,
            "%s" % response, destination, response=True, sign=True
        )
        return http_args['data'], 200

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
                raise KeyError('Errore modalità https: Chiave e/o certificato assenti!')
            _cnf['ssl_context'] = (cert, key,)
        return _cnf

    def start(self):
        """
        Start the server instance
        """
        self.app.run(
            **self._wsgiconf
        )


def _get_config(f_name, f_type='yaml'):
    """
    Read server configuration from a json file
    """
    with open(f_name, 'r') as fp:
        if f_type == 'yaml':
            return yaml.load(fp)
        elif f_type == 'json':
            return json.loads(fp.read())


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='path', help='Path to configuration file.', default='./config.yaml')
    parser.add_argument('-ct', dest='configuration_type', help='Configuration type [yaml|json]', default='yaml')
    args = parser.parse_args()
    # Init server
    config = _get_config(args.path, args.configuration_type)
    try:
        server = IdpServer(app=Flask(__name__), config=config)
        # Start server
        server.start()
    except BadConfiguration as e:
        print(e)
