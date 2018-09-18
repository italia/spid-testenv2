# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from collections import namedtuple
from datetime import datetime, timedelta

import importlib_resources
from lxml import etree
from voluptuous import All, In, Invalid, MultipleInvalid, Optional, Schema
from voluptuous.validators import Equal

from testenv import config
from testenv.exceptions import (
    GroupValidationError, SPIDValidationError, StopValidation, UnknownEntityIDError, ValidationError,
    XMLFormatValidationError, XMLSchemaValidationError,
)
from testenv.settings import (
    BINDING_HTTP_POST, DEFAULT_LIST_VALUE_ERROR, DEFAULT_VALUE_ERROR, DS as SIGNATURE, NAMEID_FORMAT_ENTITY,
    NAMEID_FORMAT_TRANSIENT, SAML as ASSERTION, SAMLP as PROTOCOL, SPID_LEVELS, TIMEDELTA,
)
from testenv.translation import Libxml2Translator
from testenv.utils import saml_to_dict, str_to_datetime, str_to_struct_time

ValidationDetail = namedtuple(
    'ValidationDetail',
    ['value', 'line', 'column', 'domain_name', 'type_name', 'message', 'path']
)


class ValidatorGroup(object):
    def __init__(self, validators):
        self._validators = validators
        self._validation_errors = []

    def validate(self, data):
        self._run(data)
        if self._validation_errors:
            raise GroupValidationError(self._validation_errors)

    def _run(self, data):
        try:
            self._run_validators(data)
        except StopValidation:
            pass

    def _run_validators(self, data):
        for validator in self._validators:
            self._run_validator(validator, data)

    def _run_validator(self, validator, data):
        try:
            validator.validate(data)
        except XMLFormatValidationError as e:
            self._handle_blocking_error(e)
        except ValidationError as e:
            self._handle_nonblocking_error(e)

    def _handle_blocking_error(self, error):
        self._handle_nonblocking_error(error)
        raise StopValidation

    def _handle_nonblocking_error(self, error):
        self._validation_errors += error.details


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


class XMLMetadataFormatValidator(XMLFormatValidator):
    def validate(self, xmlstr):
        try:
            etree.fromstring(xmlstr, parser=self._parser)
        except SyntaxError as e:
            self._handle_errors()


class XMLSchemaFileLoader(object):
    """
    Load XML Schema instances from the filesystem.
    """

    _schema_files = {
        'protocol': 'saml-schema-protocol-2.0.xsd',
        'metadata': 'saml-schema-metadata-2.0.xsd',
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


class ServiceProviderMetadataXMLSchemaValidator(BaseXMLSchemaValidator):
    def validate(self, metadata):
        schema_type = 'metadata'
        return self._run(metadata, schema_type)


class SpidValidator(object):

    def __init__(self, action, binding, registry=None, conf=None):
        self._action = action
        self._binding = binding
        self._config = conf or config.params
        if registry:  # FIXME fix circular import. this is ugly.
            self._registry = registry
        else:
            from testenv import spmetadata
            self._registry = spmetadata.registry

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
        if self._action == 'login':
            req_type = 'AuthnRequest'
        elif self._action == 'logout':
            req_type = 'LogoutRequest'
        issuer_name = data.get(
            '{urn:oasis:names:tc:SAML:2.0:protocol}%s' % (req_type), {}
        ).get(
            'children', {}
        ).get(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Issuer', {}
        ).get('text')
        if issuer_name is None:
            raise UnknownEntityIDError(
                'Issuer non presente nella {}'.format(req_type)
            )
        if issuer_name and issuer_name not in self._registry.service_providers:
            raise UnknownEntityIDError(
                'entity ID {} non registrato'.format(issuer_name)
            )
        sp_metadata = self._registry.get(issuer_name)
        if sp_metadata is not None:
            atcss = sp_metadata.attribute_consuming_services
            attribute_consuming_service_indexes = [
                str(
                    el.get('attrs').get('index')
                ) for el in atcss if 'index' in el.get('attrs', {})
            ]
            ascss = sp_metadata.assertion_consumer_services
            assertion_consumer_service_indexes = [str(el.get('index')) for el in ascss]
            assertion_consumer_service_urls = [str(el.get('Location')) for el in ascss]
        else:
            attribute_consuming_service_indexes = []
            assertion_consumer_service_indexes = []
            assertion_consumer_service_urls = []
        entity_id = self._config.entity_id

        issuer = Schema(
            {
                'attrs': {
                    'Format': Equal(
                        NAMEID_FORMAT_ENTITY, msg=DEFAULT_VALUE_ERROR.format(NAMEID_FORMAT_ENTITY)
                    ),
                    'NameQualifier': Equal(
                            issuer_name, msg=DEFAULT_VALUE_ERROR.format(issuer_name)
                        ),
                },
                'children': {},
                'text': str,
            },
            required=True,
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
            },
            required=True,
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
            required=True,
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
            required=True,
        )

        authn_context_class_ref = Schema(
            {
                'attrs': {},
                'children': {},
                'text': All(str, In(SPID_LEVELS, msg=DEFAULT_LIST_VALUE_ERROR.format(SPID_LEVELS)))
            },
            required=True,
        )

        requested_authn_context = Schema(
            {
                'attrs': {
                    'Comparison': str
                },
                'children': {
                    '{%s}AuthnContextClassRef' % (ASSERTION): authn_context_class_ref
                },
                'text': None
            },
            required=True,
        )

        scoping = Schema(
            {
                'attrs': {
                    'ProxyCount': Equal('0', msg=DEFAULT_VALUE_ERROR.format('0'))
                },
                'children': {},
                'text': None
            },
            required=True,
        )

        signature = Schema(
            {
                'attrs': dict,
                'children': dict,
                'text': None
            },
            required=True,
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
            },
            required=True,
        )

        # LOGIN

        def check_assertion_consumer_service(attrs):
            keys = attrs.keys()
            if (
                'AssertionConsumerServiceURL' in keys
                and 'ProtocolBinding' in keys
                and 'AssertionConsumerServiceIndex' not in keys
            ):
                _errors = []
                if attrs['ProtocolBinding'] != BINDING_HTTP_POST:
                    _errors.append(
                    Invalid(
                        DEFAULT_VALUE_ERROR.format(BINDING_HTTP_POST), path=['ProtocolBinding']
                    )
                    )
                if attrs['AssertionConsumerServiceURL'] not in assertion_consumer_service_urls:
                    _errors.append(
                        Invalid(
                        DEFAULT_VALUE_ERROR.format(assertion_consumer_service_urls), path=['AssertionConsumerServiceURL'])
                    )
                if _errors:
                    raise MultipleInvalid(errors=_errors)
                return attrs

            elif (
                'AssertionConsumerServiceURL' not in keys
                and 'ProtocolBinding' not in keys
                and 'AssertionConsumerServiceIndex' in keys
            ):
                if attrs['AssertionConsumerServiceIndex'] not in assertion_consumer_service_indexes:
                    raise Invalid(
                        DEFAULT_LIST_VALUE_ERROR.format(assertion_consumer_service_indexes),
                        path=['AssertionConsumerServiceIndex'])
                return attrs

            else:
                raise Invalid('Uno e uno solo uno tra gli attributi o gruppi di attributi devono essere presenti: '
                              '[AssertionConsumerServiceIndex, [AssertionConsumerServiceUrl, ProtocolBinding]]')

        authnrequest_attr_schema = Schema(
            All(
                {
                    'ID': str,
                    'Version': Equal('2.0', msg=DEFAULT_VALUE_ERROR.format('2.0')),
                    'IssueInstant': All(str, self._check_utc_date, self._check_date_in_range),
                    'Destination': Equal(
                        entity_id, msg=DEFAULT_VALUE_ERROR.format(entity_id)
                    ),
                    Optional('ForceAuthn'): str,
                    Optional('AttributeConsumingServiceIndex'): In(
                        attribute_consuming_service_indexes,
                        msg=DEFAULT_LIST_VALUE_ERROR.format(attribute_consuming_service_indexes)
                    ),
                    Optional('AssertionConsumerServiceIndex'): str,
                    Optional('AssertionConsumerServiceURL'): str,
                    Optional('ProtocolBinding'): str,
                },
                check_assertion_consumer_service,
            ),
            required=True
        )

        AUTHNREQUEST_TAG = '{%s}AuthnRequest' % (PROTOCOL)

        authnrequest_schema = {
            AUTHNREQUEST_TAG: {
                'attrs': authnrequest_attr_schema,
                'children': Schema(
                    {
                        Optional('{%s}Subject' % (ASSERTION)): subject,
                        '{%s}Issuer' % (ASSERTION): issuer,
                        '{%s}NameIDPolicy' % (PROTOCOL): name_id_policy,
                        Optional('{%s}Conditions' % (ASSERTION)): conditions,
                        '{%s}RequestedAuthnContext' % (PROTOCOL): requested_authn_context,
                        Optional('{%s}Scoping' % (PROTOCOL)): scoping,
                    },
                    required=True,
                ),
                'text': None
            }
        }

        # LOGOUT

        LOGOUTREQUEST_TAG = '{%s}LogoutRequest' % (PROTOCOL)

        logoutrequest_attr_schema = Schema(
            All(
                {
                    'ID': str,
                    'Version': Equal('2.0', msg=DEFAULT_VALUE_ERROR.format('2.0')),
                    'IssueInstant': All(str, self._check_utc_date, self._check_date_in_range),
                    'Destination': Equal(
                        entity_id, msg=DEFAULT_VALUE_ERROR.format(entity_id)
                    )
                }
            ),
            required=True
        )

        logoutrequest_schema = {
            LOGOUTREQUEST_TAG: {
                'attrs': logoutrequest_attr_schema,
                'children': Schema(
                    {
                        '{%s}Issuer' % (ASSERTION): issuer,
                        '{%s}NameID' % (ASSERTION): name_id,
                        '{%s}SessionIndex' % (PROTOCOL): dict,
                    },
                    required=True
                ),
                'text': None
            }
        }

        if self._binding == BINDING_HTTP_POST:
            if self._action == 'login':
                # Add signature schema
                _new_sub_schema = authnrequest_schema[
                    AUTHNREQUEST_TAG
                ]['children'].extend(
                        {
                            '{%s}Signature' % (SIGNATURE) : signature
                        }
                    )
                authnrequest_schema[AUTHNREQUEST_TAG]['children'] = _new_sub_schema
            if self._action == 'logout':
                _new_sub_schema = logoutrequest_schema[
                    LOGOUTREQUEST_TAG
                ]['children'].extend(
                        {
                            '{%s}Signature' % (SIGNATURE) : signature
                        }
                    )
                logoutrequest_schema[LOGOUTREQUEST_TAG]['children'] = _new_sub_schema

        authn_request = Schema(
            authnrequest_schema,
            required=True,
        )

        logout_request = Schema(
            logoutrequest_schema,
            required=True,
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
                _paths = []
                _attr = None
                for idx, _path in enumerate(err.path):
                    if _path != 'children':
                        if _path == 'attrs':
                            try:
                                _attr = err.path[(idx + 1)]
                            except IndexError:
                                _attr = ''
                            break
                        _paths.append(_path)
                path = '/'.join(_paths)
                path = 'xpath: {}'.format(path)
                if _attr is not None:
                    path = '{} - attribute: {}'.format(path, _attr)
                for _ in err.path:
                    _val = _val.get(_)
                errors.append(
                    ValidationDetail(
                        _val, None, None, None, None, err.msg, path
                    )
                )
            raise SPIDValidationError(details=errors)
