# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import collections
import json
import logging
import lxml.etree as etree
import os
import os.path
import random
import string
from datetime import datetime, timedelta
from faker import Faker
from hashlib import sha1, sha512
from logging.handlers import RotatingFileHandler

import saml2.xmldsig as ds
import yaml
from flask import Flask, Response, abort, escape, redirect, render_template_string, request, session, url_for, \
    render_template
from passlib.hash import sha512_crypt
from saml2 import (BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_URI,
                   NAMESPACE, time_util)
from saml2.assertion import Assertion
from saml2.authn_context import AuthnBroker, authn_context_class_ref
from saml2.config import Config as Saml2Config
from saml2.metadata import create_metadata_string
from saml2.request import AuthnRequest
from saml2.saml import NAME_FORMAT_BASIC, NAMEID_FORMAT_TRANSIENT, NAMEID_FORMAT_ENTITY
from saml2.server import Server
from saml2.sigver import verify_redirect_signature
from saml2.s_utils import OtherError, UnknownSystemEntity
from saml2.samlp import STATUS_AUTHN_FAILED

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

FAKER = Faker('it_IT')

SIGN_ALG = ds.SIG_RSA_SHA512
DIGEST_ALG = ds.DIGEST_SHA512
TIMEDELTA = 2

COMPARISONS = ['exact', 'minimum', 'better', 'maximum']
SPID_LEVELS = [
    'https://www.spid.gov.it/SpidL1',
    'https://www.spid.gov.it/SpidL2',
    'https://www.spid.gov.it/SpidL3'
]

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
                    <td>{{msg}}</td>
                    <td>{{extra}}</td>
                </tr>
            </tbody>
        </table>
    </body>
</html>
'''

spid_error_table = '''
<html>
    <head>
    <script src="https://code.jquery.com/jquery-3.3.1.js"></script>
    </head>
    <body>
        <div id="message">
            {% for line in lines %}
                <pre class="xml-line">{{line}}</pre>
            {% endfor %}
        </div>
        <table class="spid-error" border=1>
            <thead>
                <tr>
                    <th>Elemento</th>
                    <th>Dettagli errore</th>
                </tr>
            </thead>
            <tbody>
                {% for err in errors %}
                    <tr>
                        <td class="spid-error__elem" id="{{err.1}}">{{err.1}}</td>
                        <td>
                        <ul>
                            {% for name, msgs in err.2.items() %}
                                <li>{{name}}
                                    <ul>
                                        {% for type, msg in msgs.items() %}
                                            <li>{{msg|safe}}</li>
                                        {% endfor %}
                                    </ul>
                                </li>
                            {% endfor %}
                        </ul>
                        </td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>

    <script type="text/javascript">
        $(document).ready(function(){
            $.each($('.spid-error__elem'), function(){
                var id = $(this).attr('id');
                var line = $('.xml-line:contains("<' + id + '")');
                var tag = line[0];
                $(tag).css('background-color', 'red');
            });
        });
    </script>
    </body>
</html>
'''

FORM_LOGIN = '''
<form name="login" method="post" action="{{action}}">
   <input type="hidden" name="request_key" value="{{request_key}}" />
   <input type="hidden" name="relay_state" value="{{relay_state}}" />
   <span>Username</span> <input type="text" name="username" /><br>
   <span>Password</span> <input type="password" name="password" /><br>
   {{extra_challenge|safe}}
   <input type="submit"/>
</form>
'''

FORM_ADD_USER = '''
<form name="add_user" method="post" action="{{action}}">
   <b>Credentials</b><br>
   <span>Username</span> <input type="text" name="username" /><br>
   <span>Password</span> <input type="password" name="password" /><br>
   <span>Service provider id</span> <input type="text" name="service_provider" /><br>
   <br>
   <b>Attributi primari</b>
   <br>
    {% for attribute in primary_attributes %}
        <span>{{attribute}}</span> <input type="text" name="{{attribute}}" /><br>
    {% endfor %}
   <br>
   <b>Attributi secondari</b>
   <br>
    {% for attribute in secondary_attributes %}
        <span>{{attribute}} </span><input type="text" name="{{attribute}}" /><br>
    {% endfor %}
    <br>
   <input type="submit"/>
</form>
'''

CONFIRM_PAGE = '''
<html>
    <head>
    </head>
    <body>
        <div id="message">
            {% for line in lines %}
                <pre class="xml-line">{{line}}</pre>
            {% endfor %}
        </div>
        Vuoi trasmettere i seguenti attributi?
        <table border=1>
            <thead>
                <tr>
                    <th>attributo</th>
                </tr>
            </thead>
            <tbody>
                {% for attr in attrs %}
                    <tr>
                        <td>{{attr}}</td>
                    </tr>
                {% endfor %}
            </tbody>
        </table>
        <form name="make_response" method="post" action="{{action}}">
            <input type="hidden" name="request_key" value="{{request_key}}" />
            <input type="submit"/>
        </form>
    </body>
</html>
'''

AUTH_FAILED_ATTEMPTS = 19
AUTH_WRONG_SPID_LEVEL = 20
AUTH_TIMEOUT = 21
AUTH_NO_CONSENT = 22
AUTH_BLOCKED_CREDENTIALS = 23

SPID_ERRORS = {
    AUTH_FAILED_ATTEMPTS: STATUS_AUTHN_FAILED,
    AUTH_WRONG_SPID_LEVEL : STATUS_AUTHN_FAILED,
    AUTH_TIMEOUT: STATUS_AUTHN_FAILED,
    AUTH_NO_CONSENT : STATUS_AUTHN_FAILED,
    AUTH_BLOCKED_CREDENTIALS: STATUS_AUTHN_FAILED
}

def get_spid_error(code):
    error_type = SPID_ERRORS.get(code)
    return error_type, 'ErrorCode nr{}'.format(code)
class SPidAuthnRequest(AuthnRequest):
    def verify(self):
        # TODO: move here a bit of parsing flow
        return self


class SpidServer(Server):
    def parse_authn_request(self, enc_request, binding=BINDING_HTTP_REDIRECT):
        """Parse a Authentication Request

        :param enc_request: The request in its transport format
        :param binding: Which binding that was used to transport the message
            to this entity.
        :return: A request instance
        """

        return self._parse_request(enc_request, SPidAuthnRequest,
                                   "single_sign_on_service", binding)



def check_utc_date(date):
    try:
        time_util.str_to_time(date)
    except Exception as e:
        return False
    return True
check_utc_date.error_msg = 'la data non è in formato UTC'


def str_to_time(val):
    try:
        return datetime.strptime(val, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        try:
            return datetime.strptime(val, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            pass


def prettify_xml(msg):
    msg = etree.tostring(etree.XML(msg.encode('utf-8')), pretty_print=True, encoding='utf-8')
    return msg.decode()


class Observer(object):

    def __init__(self, *args, **kwargs):
        self._pool = collections.OrderedDict()

    def attach(self, obj):
        self._pool[obj._name] = obj
        for _child in obj._children:
            self.attach(_child)

    def evaluate(self):
        _errors = []
        for elem, obj in self._pool.items():
            if obj._errors:
                _errors.append([elem, obj._tag, obj._errors])
        return _errors


class Attr(object):
    """
    Define an attribute for a SAML2 element
    """

    MANDATORY_ERROR = 'L\'attributo è obbligatorio'
    NO_WANT_ERROR = 'L\'attributo non è richiesto'
    DEFAULT_VALUE_ERROR = '{} è diverso dal valore di riferimento {}'
    DEFAULT_LIST_VALUE_ERROR = '{} non corrisponde a nessuno dei valori contenuti in {}'
    LIMITS_VALUE_ERROR = '{} non è compreso tra {} e {}'

    def __init__(self, name, absent=False, required=True, default=None, limits=None, func=None, val_converter=None, *args, **kwargs):
        """
        :param name: attribute name
        :param required: flag to indicate if the attribute is mandatory (True by default)
        :param default: default value (or list of values, to be compared with the provided value to the 'validate' method)
        :param func: optional additional function to perform a validation on value passed to 'validated' method
        """
        self._name = name
        self._absent = absent
        self._required = required
        self._errors = {}
        self._default = default
        self._func = func
        self._limits = limits
        self._val_converter = val_converter

    def validate(self, value=None):
        """
        :param value: attribute value
        """
        if self._absent and value is not None:
            self._errors['no_want_error'] = self.NO_WANT_ERROR
        else:
            if self._required and value is None:
                self._errors['required_error'] = self.MANDATORY_ERROR
            if self._default is not None and value is not None:
                if isinstance(self._default, list) and value not in self._default:
                    self._errors['value_error'] = self.DEFAULT_LIST_VALUE_ERROR.format(value, self._default)
                elif isinstance(self._default, str) and self._default != value:
                    self._errors['value_error'] = self.DEFAULT_VALUE_ERROR.format(value, self._default)
            if self._limits is not None and value is not None:
                if self._val_converter:
                    value = self._val_converter(value)
                lower, upper = self._limits
                if value > upper or value < lower:
                    self._errors['limits_error'] = self.LIMITS_VALUE_ERROR.format(value, lower, upper)
            if self._func is not None and value is not None:
                if not self._func(value):
                    self._errors['validation_error'] = self._func.error_msg
        return {
            'value': value if not self._errors else None,
            'errors': self._errors
        }

    @property
    def real_name(self):
        if self._name == 'id':
            return 'ID'
        else:
            parsed_elements = []
            for el in self._name.split('_'):
                _new_element = el[0].upper() + el[1:]
                parsed_elements.append(_new_element)
            return ''.join(parsed_elements)


class TimestampAttr(Attr):

    RANGE_TIME_ERROR = '{} non è compreso tra {} e {}'

    def validate(self, value=None):
        validation = super(TimestampAttr, self).validate(value)
        value = self._val_converter(value)
        now = datetime.utcnow()
        lower = now - timedelta(minutes=TIMEDELTA)
        upper = now + timedelta(minutes=TIMEDELTA)
        if value < lower or value > upper:
            validation['errors']['range_time_error'] = self.RANGE_TIME_ERROR.format(value, lower, upper)
        return validation



class Elem(object):
    """
    Define a SAML2 element
    """

    MANDATORY_ERROR = 'L\'elemento è obbligatorio'
    NO_WANT_ERROR = 'L\'elemento non è richiesto'

    def __init__(self, name, tag, absent=False, required=True, attributes=[], children=[], example='', *args, **kwargs):
        """
        :param name: element name
        :param tag: element 'namespace:tag_name'
        :param required: flag to indicate if the element is mandatory (True by default)
        :param attributes: list of Attr objects (element attributes)
        :param children: list of Elem objects (nested elements)
        :param example: string to explain how the missing element need to be implemented
        """
        self._name = name
        self._required = required
        self._absent = absent
        self._attributes = attributes
        self._children = children
        self._errors = {}
        self._tag = tag
        self._example = example

    def validate(self, data):
        """
        :param data: (nested) object returned by pysaml2
        """
        res = { 'attrs': {}, 'children': {}, 'errors': {} }
        if self._absent and data is not None:
            res['errors']['no_want_error'] = self.NO_WANT_ERROR
            self._errors.update(res['errors'])
        else:
            if self._required and data is None:
                # check if the element is required, if not provide and example
                _error_msg = self.MANDATORY_ERROR
                _example = '<br>Esempio:<br>'
                lines = self._example.splitlines()
                for line in lines:
                    _example = '{}<pre>{}</pre>'.format(_example, escape(line))
                _error_msg = '{} {}'.format(_error_msg, _example)
                res['errors']['required_error'] = _error_msg
                self._errors.update(res['errors'])
            if data:
                if isinstance(data, list):
                    # TODO: handle list elements in a clean way
                    data = data[0]
                for attribute in self._attributes:
                    _validated_attributes = attribute.validate(getattr(data, attribute._name))
                    res['attrs'][attribute.real_name] = _validated_attributes
                    if _validated_attributes['errors']:
                        self._errors.update({attribute.real_name: _validated_attributes['errors']})
                for child in self._children:
                    res['children'][child._name] = child.validate(getattr(data, child._name))
        return res


class SpidParser(object):
    """
    Parser for spid messages
    """

    def __init__(self, *args, **kwargs):
        self.schema = None

    def get_schema(self, action, binding, **kwargs):
        """
        :param binding:
        """
        _schema = None
        if action == 'login':
            required_signature = False
            if binding == BINDING_HTTP_POST:
                required_signature = True
            elif binding == BINDING_HTTP_REDIRECT:
                required_signature = False
            attribute_consuming_service_indexes = kwargs.get('attribute_consuming_service_indexes')
            receivers = kwargs.get('receivers')
            _schema = Elem(
                name='auth_request',
                tag='samlp:AuthnRequest',
                attributes=[
                    Attr('id'),
                    Attr('version', default='2.0'),
                    TimestampAttr('issue_instant', func=check_utc_date, val_converter=str_to_time),
                    Attr('destination', default=receivers),
                    Attr('force_authn', required=False),
                    Attr('attribute_consuming_service_index', default=attribute_consuming_service_indexes, required=False),
                    Attr('assertion_consumer_service_url', required=False),
                    Attr('protocol_binding', default=BINDING_HTTP_POST, required=False)
                ],
                children=[
                    Elem(
                        'subject',
                        tag='saml:Subject',
                        required=False,
                        attributes=[
                            Attr('format', default=NAMEID_FORMAT_ENTITY),
                            Attr('name_qualifier')
                        ]
                    ),
                    Elem(
                        'issuer',
                        tag='saml:Issuer',
                        example='''
                            <saml:Issuer
                                NameQualifier="http://spid.serviceprovider.it"
                                Format="{}">
                                spid-sp
                            </saml:Issuer>
                        '''.format(NAMEID_FORMAT_ENTITY),
                        attributes=[
                            Attr('format', default=NAMEID_FORMAT_ENTITY),
                            Attr('name_qualifier')
                        ],
                    ),
                    Elem(
                        'name_id_policy',
                        tag='samlp:NameIDPolicy',
                        attributes=[
                            Attr('allow_create', absent=True, required=False),
                            Attr('format', default=NAMEID_FORMAT_TRANSIENT)
                        ]
                    ),
                    Elem(
                        'conditions',
                        tag='saml:Conditions',
                        required=False,
                        attributes=[
                            Attr('not_before', func=check_utc_date),
                            Attr('not_on_or_after', func=check_utc_date)
                        ]
                    ),
                    Elem(
                        'requested_authn_context',
                        tag='saml:AuthnContext',
                        attributes=[
                            Attr('comparison', default=COMPARISONS),
                        ],
                        children=[
                            Elem(
                                'authn_context_class_ref',
                                tag='saml:AuthnContextClassRef',
                                attributes=[
                                    Attr('text', default=SPID_LEVELS)
                                ]
                            )
                        ]
                    ),
                    Elem(
                        'signature',
                        tag='ds:Signature',
                        required=required_signature,
                    ),
                    Elem(
                        'scoping',
                        tag='saml2p:Scoping',
                        required=False,
                        attributes=[
                            Attr('proxy_count', default=[0])
                        ]
                    ),
                ]
            )
        elif action == 'logout':
            _schema = Elem(
                name='logout_request',
                tag='samlp:LogoutRequest',
                attributes=[
                    Attr('id'),
                    Attr('version', default='2.0'),
                    Attr('issue_instant', func=check_utc_date),
                    Attr('destination'),
                ],
                children=[
                    Elem(
                        'issuer',
                        tag='saml:Issuer',
                        example='''
                            <saml:Issuer
                                NameQualifier="http://spid.serviceprovider.it"
                                Format="{}">
                                spid-sp
                            </saml:Issuer>
                        '''.format(NAMEID_FORMAT_ENTITY),
                        attributes=[
                            Attr('format', default=NAMEID_FORMAT_ENTITY),
                            Attr('name_qualifier')
                        ],
                    ),
                    Elem(
                        'name_id',
                        tag='saml:NameID',
                        attributes=[
                            Attr('name_qualifier'),
                            Attr('format', default=NAMEID_FORMAT_TRANSIENT)
                        ]
                    ),
                    Elem(
                        'session_index',
                        tag='samlp:SessionIndex',
                    ),
                ]
            )
        return _schema

    def parse(self, obj, action, binding, schema=None, **kwargs):
        """
        :param obj: pysaml2 object
        :param binding:
        :param schema: custom schema (None by default)
        """
        _schema = self.get_schema(action, binding, **kwargs) if schema is None else schema
        self.observer = Observer()
        self.observer.attach(_schema)
        validated = _schema.validate(obj)
        errors = self.observer.evaluate()
        return validated, errors


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
            for idx, _ in enumerate(range(10)):
                _is_even = (idx % 2 == 0)
                self.users[FAKER.user_name()] = {
                    'attrs': {
                        'spidCode': FAKER.uuid4(),
                        'name': FAKER.first_name_male() if _is_even else FAKER.first_name_female(),
                        'familyName': FAKER.last_name_male() if _is_even else FAKER.last_name_female(),
                        'gender': 'M' if _is_even else 'F',
                        'birthDate': FAKER.date(),
                        'companyName': FAKER.company(),
                        'registeredOffice': FAKER.address(),
                        'email': FAKER.email()
                    },
                    'pwd': 'test',
                    'sp': None
                }
            self._save()

    def _save(self):
        with open(self.FILE_NAME, 'w') as fp:
            json.dump(self.users, fp, indent=4)

    def __init__(self, *args, **kwargs):
        self._load()

    def get(self, uid, pwd, sp_id):
        for user, _attrs in self.users.items():
            if pwd == _attrs['pwd']:
                if _attrs['sp'] is not None and _attrs['sp'] != sp_id:
                    return None, None
                return user, self.users[user]
        return None, None

    def add(self, uid, pwd, sp_id=None, extra={}):
        if uid not in self.users:
            self.users[uid] = {
                'pwd': pwd,
                'sp': sp_id,
                'attrs': extra
            }
        self._save()

    def all(self):
        return self.users


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
        self.app.add_url_rule('/', 'index', self.index, methods=['GET'])
        self.app.add_url_rule('/login', 'login', self.login, methods=['POST', 'GET',])
        # Endpoint for user add action
        self.app.add_url_rule('/users', 'users', self.users, methods=['GET', 'POST',])
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
               render_template(
                    "error.html",
                    **{'msg': msg, 'extra': extra or ""}
                ),
                200
            )
        )

    def _check_spid_restrictions(self, msg, action, binding, **kwargs):
        parsed_msg, errors = self.spid_parser.parse(msg.message, action, binding, **kwargs)
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
                if 'SAMLRequest' not in saml_msg:
                    self._raise_error('Parametro SAMLRequest assente.')
                req_info = self.server.parse_authn_request(
                    saml_msg['SAMLRequest'],
                    binding
                )
                authn_req = req_info.message
                extra = {}
                sp_id = authn_req.issuer.text
                issuer_name = authn_req.issuer.text
                # TODO: refactor a bit fetching this kind of data from pysaml2
                acss = self.server.metadata.assertion_consumer_service(sp_id, authn_req.protocol_binding)
                acss_indexes = [str(el.get('index')) for el in acss]
                extra['attribute_consuming_service_indexes'] = acss_indexes
                extra['receivers'] = req_info.receiver_addrs
                _, errors = self._check_spid_restrictions(req_info, 'login', binding, **extra)
            except UnknownSystemEntity as err:
                self.app.logger.debug(str(err))
                self._raise_error('entity ID {} non registrato.'.format(issuer_name))

            if errors:
                return self._handle_errors(errors, req_info.xmlstr)

            if not req_info:
                self._raise_error('Processo di parsing del messaggio fallito.')

            self.app.logger.debug('AuthnRequest: \n{}'.format(prettify_xml(str(authn_req))))
            # Check if it is signed
            if "SigAlg" in saml_msg and "Signature" in saml_msg:
                # Signed request
                self.app.logger.debug('Messaggio SAML firmato.')
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
                'sp_list': [{"name": sp, "spId": sp} for sp in self.server.metadata.service_providers()],
            }
        )
        return rendered_form, 200

    def get_destination(self, req, sp_id):
        destination = None
        if req.message.attribute_consuming_service_index is not None:
            acss = self.server.metadata.assertion_consumer_service(sp_id, req.message.protocol_binding)
            for acs in acss:
                if acs.get('index') == req.message.attribute_consuming_service_index:
                    destination = acs.get('location')
                    break
            self.app.logger.debug('AssertionConsumingServiceIndex Location: {}'.format(destination))
        if destination is None:
            destination = req.message.assertion_consumer_service_url
            self.app.logger.debug('AssertionConsumerServiceUrl: {}'.format(destination))
        return destination

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
            destination = self.get_destination(authn_request, sp_id)
            spid_level = authn_request.message.requested_authn_context.authn_context_class_ref[0].text
            authn_info = self.authn_broker.pick(authn_request.message.requested_authn_context)
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
                        self.app.logger.debug('Response: \n{}'.format(response))
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
                        rendered_response = render_template(
                            'confirm.html',
                            **{
                                'destination_service': sp_id,
                                'lines':  escape(prettify_xml(response)).splitlines(),
                                'attrs': attrs,
                                'action': '/continue-response',
                                'request_key': key
                            }
                        )
                        return rendered_response, 200
            elif 'delete' in request.form:
                error_response = self.server.create_error_response(
                    in_response_to=authn_request.message.id,
                    destination=destination,
                    info=get_spid_error(AUTH_NO_CONSENT)
                )
                self.app.logger.debug('Error response: \n{}'.format(prettify_xml(str(error_response))))
                http_args = self.server.apply_binding(
                    BINDING_HTTP_POST,
                    error_response,
                    destination,
                    response=True,
                    sign=True,
                    relay_state=relay_state
                )
                return http_args['data'], 200
        return render_template('403.html'), 403

    def continue_response(self):
        key = request.form['request_key']
        if key and key in self.ticket and key in self.responses:
            if 'confirm' in request.form:
                return self.responses[key], 200
            elif 'delete' in request.form:
                auth_req = self.ticket[key]
                destination = self.get_destination(auth_req, auth_req.message.issuer.text)
                error_response = self.server.create_error_response(
                    in_response_to=auth_req.message.id,
                    destination=destination,
                    info=get_spid_error(AUTH_NO_CONSENT)
                )
                self.app.logger.debug('Error response: \n{}'.format(prettify_xml(str(error_response))))
                http_args = self.server.apply_binding(
                    BINDING_HTTP_POST,
                    error_response,
                    destination,
                    response=True,
                    sign=True,
                )
                return http_args['data'], 200
        return render_template('403.html'), 403

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
        _, errors = self._check_spid_restrictions(req_info, 'logout', _binding)
        if errors:
            return self._handle_errors(errors, req_info.xmlstr)
        response = self.server.create_logout_response(
            msg, [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT],
            sign_alg=SIGN_ALG,
            digest_alg=DIGEST_ALG,
            sign=True
        )
        self.app.logger.debug('Response: \n{}'.format(response))
        binding, destination = self.server.pick_binding(
            "single_logout_service",
            [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT], "spsso",
            req_info
        )
        http_args = self.server.apply_binding(
            binding,
            "%s" % response, destination, response=True, sign=True
        )
        if binding == BINDING_HTTP_POST:
            return http_args['data'], 200
        elif binding == BINDING_HTTP_REDIRECT:
            headers = dict(http_args['headers'])
            location = headers.get('Location')
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
        os.environ['FLASK_ENV'] = 'development'
        server = IdpServer(app=Flask(__name__, static_url_path='/static'), config=config)
        # Start server
        server.start()
    except BadConfiguration as e:
        print(e)
