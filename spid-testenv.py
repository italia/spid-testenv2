# -*- coding: utf-8 -*-
import argparse
import json
import os.path
import random
import string
from datetime import datetime
from hashlib import sha1, sha512

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
from saml2.saml import NAMEID_FORMAT_TRANSIENT, NAME_FORMAT_BASIC
from saml2.server import Server
from saml2.sigver import verify_redirect_signature

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'


SIGN_ALG  = ds.SIG_RSA_SHA1

error_table = '''
<html>
    <head>
    </head>
    <body>
        <table border=1>
            <thead>
                <tr>
                    <th>Error</th>
                    <th>Detail(s)</th>
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
        Do you want to transmit the following attributes?
        <table border=1>
            <thead>
                <tr>
                    <th>attribute</th>
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
    def _load(self):
        with open('users.json', 'r') as fp:
            self.users = json.loads(fp.read())

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
        with open('users.json', 'w') as fp:
            json.dump(self.users, fp, indent=4)



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

    def __init__(self, app, config, *args, **kwargs):
        # bind Flask app
        self.app = app
        self.user_manager = JsonUserManager()
        # setup
        self._config = config
        self.app.secret_key = self._config.get('secret_key')
        self._prepare_server(config)

    def _idp_config(self):
        idp_conf = {
            "entityid": self._config.get('entityid', ''),
            "description": self._config.get('description', ''),
            "service": {
                "idp": {
                    "name": self._config.get('name', 'Spid Testenv'),
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
            "metadata": self._config.get('metadata'),
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
                    "backupCount": 5,
                },
                "loglevel": "debug",
            }
        }
        # setup services url
        for _service_type in self._endpoint_types:
            for binding, endpoint in self._config['endpoints'][_service_type].items():
                idp_conf['service']['idp']['endpoints'][_service_type].append(
                    ('{}{}'.format(self._config['entityid'], endpoint), self._binding_mapping.get(binding))
                )
        return idp_conf

    def _setup_app_routes(self):
        """
        Setup Flask routes
        """
        endpoints = self._config.get('endpoints')
        if endpoints:
            for ep_type in self._endpoint_types:
                _ep_config = endpoints.get(ep_type)
                if _ep_config:
                    for _binding, _url in _ep_config.items():
                        self.app.add_url_rule(_url, '{}_{}'.format(ep_type, _binding), getattr(self, ep_type), methods=['GET',])
        self.app.add_url_rule('/login', 'login', self.login, methods=['POST', 'GET',])
        self.app.add_url_rule('/add-user', 'add_user', self.add_user, methods=['GET', 'POST',])
        self.app.add_url_rule('/continue-response', 'continue_response', self.continue_response, methods=['POST',])

    def _prepare_server(self, config):
        """
        Setup server
        """
        self.idp_config = Saml2Config()
        if config.get('https', False):
            self.BASE = "https://%s:%s" % (config.get('host'), config.get('port'))
        else:
            self.BASE = "http://%s:%s" % (config.get('host'), config.get('port'))
        if 'entityid' not in config:
            # as fallback for entityid use host:port string
            config['entityid'] = self.BASE
        self.idp_config.load(cnf=self._idp_config())
        self.server = Server(config=self.idp_config)
        self._setup_app_routes()
        self.authn_broker = AuthnBroker()
        for index, _level in enumerate(self._spid_levels):
            self.authn_broker.add(
                authn_context_class_ref(_level),
                self.something
            )

    def something(self):
        pass

    def unpack_args(self, elems):
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

    def _check_authn_restrictions(self, authn_req):
    # TODO: implement a custom check for every pysaml2 Entity (authnrequest, logoutrequest etc.)
    # example snippet to retrieve attributes from an authn_request
    #     version = authn_req.version
    #     app.logger.debug('Version {}'.format(version))
    #     if version != VERSION:
    #         self._raise_error('Version must be "2.0"')
    #     app.logger.debug('Issue instant {}'.format(authn_req.issue_instant))
    #     app.logger.debug('Destination {}'.format(authn_req.destination))
    #     app.logger.debug('ForceAuthn {}'.format(authn_req.force_authn))
    #     assertion_consumer_service_index = authn_req.assertion_consumer_service_index
    #     app.logger.debug('AssertionConsumerServiceIndex {}'.format(authn_req.assertion_consumer_service_index))
    #     app.logger.debug('Subject {}'.format(authn_req.subject))
    #     issuer = authn_req.issuer
    #     app.logger.debug('Issuer {}'.format(issuer))
    #     app.logger.debug('Issuer Format {}'.format(issuer.format))
    #     app.logger.debug('Issuer Name qualifier {}'.format(issuer.name_qualifier))
    #     name_id_policy = authn_req.name_id_policy
    #     app.logger.debug('Name ID Policy {}'.format(name_id_policy))
    #     app.logger.debug('Name ID Policy AllowCreate {}'.format(name_id_policy.allow_create))
    #     app.logger.debug('Name ID Policy Format {}'.format(name_id_policy.format))
    #     if name_id_policy.format != NAMEID_FORMAT_TRANSIENT:
    #         self._raise_error('Name ID Policy Format is not {}'.format(NAMEID_FORMAT_TRANSIENT))
        pass

    def _store_request(self, authnreq):
        """
        Store authnrequest in a dictionary

        :param authnreq: authentication request string
        """
        self.app.logger.debug("_store_request: %s", authnreq)
        key = sha1(authnreq.xmlstr).hexdigest()
        # store the AuthnRequest
        self.ticket[key] = authnreq
        return key

    @property
    def sign_assertion(self):
        return self._config.get('sign_assertions', False)

    def process_request(self, request, binding):
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
                # Parse AuthnRequest
                req_info = self.server.parse_authn_request(
                    saml_msg["SAMLRequest"],
                    binding
                )
                authn_req = req_info.message
            except KeyError as err:
                self.app.logger.debug(str(err))
                self._raise_error('Missing SAMLRequest parameter')

            if not req_info:
                self._raise_error('Message parsing failed')

            self.app.logger.debug('AuthnRequest: {}'.format(authn_req))
            # Check if it is signed
            if "SigAlg" in saml_msg and "Signature" in saml_msg:
                # Signed request
                self.app.logger.debug('Signed request')
                issuer_name = authn_req.issuer.text
                _certs = self.server.metadata.certs(
                    issuer_name,
                    "any",
                    "signing"
                )
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
                self.app.logger.debug('Verified request')
                if not verified_ok:
                    self._raise_error('Message signature verification failure')
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

    def single_sign_on_service(self):
        """
        SSO endpoint

        :param binding: 'redirect' is http-redirect, 'post' is http-post binding
        """
        _binding = self._get_binding('single_sign_on_service', request)
        if _binding:
            return self.process_request(request, _binding)
        abort(404)

    @property
    def _spid_main_fields(self):
        return self._spid_attributes['primary'].keys()

    @property
    def _spid_secondary_fields(self):
        return self._spid_attributes['secondary'].keys()

    def add_user(self):
        """
        Add user endpoint

        FIXME: handle all spid attributes
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
            method, reference = authn_info[0]
            if request.method == 'GET':
                if reference == '2':
                    # spid level 2
                    otp = ''.join(random.choice(string.digits) for _ in range(6))
                    self.challenges[key] = [otp, datetime.now()]
                    extra_challenge = '<span>Otp ({})</span><input type="text" name="otp" />'.format(otp)
                else:
                    extra_challenge = ''
                return FORM_LOGIN.format(
                    url_for('login'),
                    key,
                    relay_state,
                    extra_challenge
                ), 200
            if reference == '2':
                # spid level 2
                if key not in self.challenges or not request.form['otp']:
                    abort(403)
                if self.challenges[key][0] != request.form['otp'] or (datetime.now() - self.challenges[key][1]).total_seconds() > self.CHALLENGES_TIMEOUT:
                    del self.challenges[key]
                    abort(403)
            # verify credentials
            user_id, user = self.user_manager.get(
                request.form['username'],
                request.form['password'],
                sp_id
            )
            if user_id is not None:
                # setup response
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
                    sign_assertion=self.sign_assertion
                )
                response = self.server.create_authn_response(
                    **_data
                )
                http_args = self.server.apply_binding(
                    BINDING_HTTP_POST,
                    response,
                    destination,
                    response=True,
                    sign=self.sign_assertion,
                    relay_state=relay_state
                )
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
            sign=self.sign_assertion
        )
        binding, destination = self.server.pick_binding(
            "single_logout_service",
            [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT], "spsso",
            req_info
        )
        http_args = self.server.apply_binding(
            binding,
            "%s" % response, destination, response=True, sign=self.sign_assertion
        )
        return http_args['data'], 200

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
                raise KeyError('Missing key or certificate needed by https mode!')
            _cnf['ssl_context'] = (cert, key,)
        return _cnf

    def start(self):
        """
        Start the server instance
        """
        self.app.run(
            **self._wsgiconf,
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
    # Init server
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='path', help='Path to configuration file.', default='./config.yaml')
    parser.add_argument('-ct', dest='configuration_type', help='Configuration type [yaml|json]', default='yaml')
    args = parser.parse_args()
    config = _get_config(args.path, args.configuration_type)
    server = IdpServer(app=Flask(__name__), config=config)
    # Start server
    server.start()
