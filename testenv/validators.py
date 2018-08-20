# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from collections import namedtuple
from datetime import datetime, timedelta

import importlib_resources
from lxml import etree
from voluptuous import ALLOW_EXTRA, All, In, Invalid, MultipleInvalid, Optional, Schema
from voluptuous.validators import Equal

from testenv.exceptions import SPIDValidationError, XMLFormatValidationError, XMLSchemaValidationError
from testenv.settings import SPID_LEVELS, TIMEDELTA
from testenv.translation import Libxml2Translator
from testenv.utils import saml_to_dict, str_to_datetime, str_to_struct_time

MANDATORY_ERROR = 'L\'attributo è obbligatorio'
NO_WANT_ERROR = 'L\'attributo non è richiesto'
DEFAULT_VALUE_ERROR = 'è diverso dal valore di riferimento {}'
DEFAULT_LIST_VALUE_ERROR = 'non corrisponde a nessuno '\
                           'dei valori contenuti in {}'
ASSERTION = '{urn:oasis:names:tc:SAML:2.0:assertion}'
PROTOCOL = '{urn:oasis:names:tc:SAML:2.0:protocol}'
SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#'

NAMEID_FORMAT_ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
NAMEID_FORMAT_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

ValidationDetail = namedtuple(
    'ValidationDetail',
    ['value', 'line', 'column', 'domain_name', 'type_name', 'message', 'path']
)


class XMLFormatValidator(object):
    """
    Ensure XML is well formed.
    """

    def __init__(self, parser=None, translator=None):
        self._parser = parser or etree.XMLParser()
        self._translator = translator or Libxml2Translator()

    def validate(self, request):
        try:
            etree.fromstring(request.saml_request, parser=self._parser)
        except SyntaxError:
            self._handle_errors()

    def _handle_errors(self):
        errors = self._build_errors()
        localized_errors = self._localize_messages(errors)
        raise XMLFormatValidationError(localized_errors)

    def _build_errors(self):
        errors = self._parser.error_log
        return [
            ValidationDetail(None, err.line, err.column, err.domain_name,
                             err.type_name, err.message, err.path)
            for err in errors
        ]

    def _localize_messages(self, errors):
        return self._translator.translate_many(errors)


class XMLSchemaFileLoader(object):
    """
    Load XML Schema instances from the filesystem.
    """

    _schema_files = {
        'protocol': 'saml-schema-protocol-2.0.xsd',
    }

    def __init__(self, import_path=None):
        self._import_path = import_path or 'testenv.xsd'

    def load(self, schema_type):
        path = self._build_path(schema_type)
        return self._parse(path)

    def _build_path(self, schema_type):
        filename = self._schema_files[schema_type]
        with importlib_resources.path(self._import_path, filename) as path:
            return path

    @staticmethod
    def _parse(path):
        xmlschema_doc = etree.parse(str(path))
        return etree.XMLSchema(xmlschema_doc)


class BaseXMLSchemaValidator(object):
    """
    Validate XML fragments against XML Schema (XSD).
    """

    def __init__(self, schema_loader=None, parser=None, translator=None):
        self._schema_loader = schema_loader or XMLSchemaFileLoader()
        self._parser = parser or etree.XMLParser()
        self._translator = translator or Libxml2Translator()

    def _run(self, xml, schema_type):
        xml_doc = self._parse_xml(xml)
        schema = self._load_schema(schema_type)
        return self._validate_xml(xml_doc, schema)

    def _parse_xml(self, xml):
        return etree.fromstring(xml, parser=self._parser)

    def _load_schema(self, schema_type):
        return self._schema_loader.load(schema_type)

    def _validate_xml(self, xml_doc, schema):
        try:
            schema.assertValid(xml_doc)
        except Exception:
            self._handle_errors(schema.error_log)

    def _handle_errors(self, error_log):
        errors = self._build_errors(error_log)
        localized_errors = self._localize_messages(errors)
        raise XMLSchemaValidationError(localized_errors)

    def _build_errors(self, error_log):
        return [
            ValidationDetail(None, err.line, err.column, err.domain_name,
                             err.type_name, err.message, err.path)
            for err in error_log
        ]

    def _localize_messages(self, errors):
        return self._translator.translate_many(errors)


class AuthnRequestXMLSchemaValidator(BaseXMLSchemaValidator):
    def validate(self, request):
        xml = request.saml_request
        schema_type = 'protocol'
        return self._run(xml, schema_type)


class SpidValidator(object):

    def __init__(self, action, binding, metadata):
        self._action = action
        self._binding = binding
        self._metadata = metadata

    def _check_utc_date(self, date):
        try:
            str_to_struct_time(date)
        except Exception:
            raise Invalid('la data non è in formato UTC')
        return date

    def _check_date_in_range(self, date):
        date = str_to_datetime(date)
        now = datetime.utcnow()
        lower = now - timedelta(minutes=TIMEDELTA)
        upper = now + timedelta(minutes=TIMEDELTA)
        if date < lower or date > upper:
            raise Invalid(
                '{} non è compreso tra {} e {}'.format(
                    date, lower, upper
                )
            )
        return date

    def validate(self, request):
        xmlstr = request.saml_request
        data = saml_to_dict(xmlstr)
        atcss = []
        if self._action == 'login':
            req_type = 'AuthnRequest'
        elif self._action == 'logout':
            req_type = 'LogoutRequest'
        issuer = data.get('{urn:oasis:names:tc:SAML:2.0:protocol}%s' % (req_type)).get('children').get('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').get('text')
        for k, _md in self._metadata.items():
            if k == issuer:
                _srvs = _md.get('spsso_descriptor', [])
                for _srv in _srvs:
                    for _acs in _srv.get(
                        'attribute_consuming_service', []
                    ):
                        atcss.append(_acs)
        try:
            ascss = self._metadata.assertion_consumer_service(issuer)
        except Exception:
            ascss = []
        except Exception:
            ascss = []
        attribute_consuming_service_indexes = [str(el.get('index')) for el in atcss]
        assertion_consumer_service_indexes = [str(el.get('index')) for el in ascss]
        receivers = data.get('{urn:oasis:names:tc:SAML:2.0:protocol}%s' % (req_type)).get('attrs').get('Destination')

        issuer = Schema(
            {
            'attrs': {
                'Format': Equal(
                    NAMEID_FORMAT_ENTITY, msg=DEFAULT_VALUE_ERROR.format(NAMEID_FORMAT_ENTITY)
                ),
                'NameQualifier': issuer
            },
            'children': {},
            'text': issuer
            }
        )

        name_id = Schema(
            {
                'attrs': {
                    'NameQualifier': str,
                    'Format': Equal(
                        NAMEID_FORMAT_TRANSIENT, msg=DEFAULT_VALUE_ERROR.format(NAMEID_FORMAT_TRANSIENT)
                    ),
                },
                'children': {},
                'text': str
            }
        )

        name_id_policy = Schema(
            {
            'attrs': {
                'Format': Equal(
                    NAMEID_FORMAT_TRANSIENT, msg=DEFAULT_VALUE_ERROR.format(NAMEID_FORMAT_TRANSIENT)
                ),
            },
            'children': {},
            'text': None,
            },
        )


        conditions = Schema(
            {
            'attrs': {
                'NotBefore': All(str, self._check_utc_date),
                'NotOnOrAfter': All(str, self._check_utc_date),
            },
            'children': {},
            'text': None,
            },
        )

        authn_context_class_ref = Schema(
            {
                'attrs': {},
                'children': {},
                'text': All(str, In(SPID_LEVELS, msg=DEFAULT_LIST_VALUE_ERROR.format(SPID_LEVELS)))
            }
        )

        requested_authn_context = Schema(
            {
                'attrs': {
                    'Comparison': str
                },
                'children': {
                    '{}AuthnContextClassRef'.format(ASSERTION): authn_context_class_ref
                },
                'text': None
            }
        )

        scoping = Schema(
            {
                'attrs': {
                    'ProxyCount': Equal('0', msg=DEFAULT_VALUE_ERROR.format('0'))
                },
                'children': {},
                'text': None
            }
        )

        signature = Schema(
            {
                'attrs': dict,
                'children': dict,
                'text': None
            }
        )

        subject = Schema(
            {
                'attrs': {
                    'Format': Equal(
                        NAMEID_FORMAT_ENTITY, msg=DEFAULT_VALUE_ERROR.format(NAMEID_FORMAT_ENTITY)
                    ),
                    'NameQualifier': str
                },
                'children': {},
                'text': None
            }
        )

        # LOGIN

        authnrequest_schema = {
            '{}AuthnRequest'.format(PROTOCOL): {
                'attrs': {
                    'Version': Equal('2.0', msg=DEFAULT_VALUE_ERROR.format('2.0')),
                    'IssueInstant': All(str, self._check_utc_date, self._check_date_in_range),
                    'Destination': In(receivers, msg=DEFAULT_LIST_VALUE_ERROR.format(receivers)),
                    Optional('ForceAuthn'): str,
                    Optional('AttributeConsumingServiceIndex'): In(
                        attribute_consuming_service_indexes,
                        msg=DEFAULT_LIST_VALUE_ERROR.format(attribute_consuming_service_indexes)
                    ),
                    Optional('AssertionConsumerServiceIndex'): In(
                        assertion_consumer_service_indexes,
                        msg=DEFAULT_LIST_VALUE_ERROR.format(assertion_consumer_service_indexes)
                    ),
                    Optional('AssertionConsumerServiceURL'): str,
                    Optional('ProtocolBinding'): Equal(
                        BINDING_HTTP_POST,
                        msg=DEFAULT_VALUE_ERROR.format( BINDING_HTTP_POST)
                    )
                },
                'children': Schema(
                    {
                        Optional('{}Subject'.format(ASSERTION)): subject,
                        '{}Issuer'.format(ASSERTION): issuer,
                        '{}NameIDPolicy'.format(PROTOCOL): name_id_policy,
                        Optional('{}Conditions'.format(ASSERTION)): conditions,
                        '{}RequestedAuthnContext'.format(PROTOCOL): requested_authn_context,
                        Optional('{}Scoping'.format(PROTOCOL)): scoping,
                    }
                ),
                'text': None
            }
        }

        if self._binding == BINDING_HTTP_POST:
            authnrequest_schema['{}AuthnRequest'.format(PROTOCOL)]['children'].extend = {'{}Signature'.format(SIGNATURE) : signature}

        authn_request = Schema(
            authnrequest_schema,
            extra=ALLOW_EXTRA
        )

        # LOGOUT

        logout_request= Schema(
            {
                '{}LogoutRequest'.format(PROTOCOL): {
                    'attrs': {
                    'Version': Equal('2.0', msg=DEFAULT_VALUE_ERROR.format('2.0')),
                    'IssueInstant': All(str, self._check_utc_date, self._check_date_in_range),
                    'Destination': In(receivers, msg=DEFAULT_LIST_VALUE_ERROR.format(receivers)),
                    },
                    'children': {
                        '{}Issuer'.format(ASSERTION): issuer,
                        '{}NameID'.format(ASSERTION): str
                    },
                    'text': None
                }
            },
            extra=ALLOW_EXTRA
        )


        saml_schema = None
        if self._action == 'login':
            saml_schema = authn_request
        elif self._action == 'logout':
            saml_schema = logout_request
        errors = []
        try:
            saml_schema(data)
        except MultipleInvalid as e:
            for err in e.errors:
                _val = data
                for _ in err.path:
                    _val = _val.get(_)
                errors.append(
                    ValidationDetail(
                        _val, None, None, None, None, err.msg, err.path
                    )
                )
            raise SPIDValidationError(details=errors)
