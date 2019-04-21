# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import re
from collections import namedtuple
from datetime import datetime, timedelta

import importlib_resources
from lxml import etree
from voluptuous import All, Any, In, Invalid, Length, Match, MultipleInvalid, Optional, Schema, Url
from voluptuous.validators import Equal

from testenv import config
from testenv.crypto import (
    load_certificate, verify_bad_certificate_algorithm, verify_certificate_algorithm, verify_certificate_expiration,
)
from testenv.exceptions import (
    GroupValidationError, MetadataNotFoundError, SPIDValidationError, StopValidation, UnknownEntityIDError,
    ValidationError, XMLFormatValidationError, XMLSchemaValidationError,
)
from testenv.settings import (
    BINDING_HTTP_POST, DEFAULT_LIST_VALUE_ERROR, DEFAULT_VALUE_ERROR, DS as SIGNATURE, KEYDESCRIPTOR_USES,
    MD as METADATA, NAME_FORMAT_BASIC, NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_TRANSIENT, SAML as ASSERTION,
    SAMLP as PROTOCOL, SPID_ATTRIBUTES_NAMES, SPID_LEVELS, TIMEDELTA,
)
from testenv.translation import Libxml2Translator
from testenv.utils import saml_to_dict, str_to_datetime, str_to_struct_time

ValidationDetail = namedtuple(
    'ValidationDetail',
    ['value', 'line', 'column', 'domain_name', 'type_name', 'message', 'path']
)


def _check_utc_date(date):
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
            'Il valore non è compreso tra {} e {}'.format(
                lower, upper
            )
        )
    return date


def _check_certificate(cert):
    _errors = []
    cert = load_certificate(cert)
    is_expired = verify_certificate_expiration(cert)
    has_supported_alg = verify_certificate_algorithm(cert)
    no_sha1 = verify_bad_certificate_algorithm(cert)
    if is_expired:
        _errors.append(
            Invalid('Il certificato è scaduto.')
        )
    if not has_supported_alg:
        _errors.append(
            Invalid('Il certificato deve essere firmato con un algoritmo valido.')
        )
    if not no_sha1:
        _errors.append(
            Invalid('Il certificato non deve essere firmato tramite algoritmo SHA1 (deprecato).')
        )
    if _errors:
        raise MultipleInvalid(errors=_errors)
    return cert


def _strip_namespaces(string):
    return re.sub(r'\{(urn|http):.+?\}', '', string)


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
        except SyntaxError:
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
        print(errors)
        localized_errors = self._localize_messages(errors)
        raise XMLSchemaValidationError(localized_errors)

    @staticmethod
    def _build_errors(error_log):
        return [
            ValidationDetail(None, err.line, err.column, err.domain_name,
                             err.type_name, _strip_namespaces(err.message), err.path)
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


class SpidMetadataValidator(object):
    def __init__(self, registry=None):
        if registry:  # FIXME fix circular import. this is ugly.
            self._registry = registry
        else:
            from testenv import spmetadata
            self._registry = spmetadata.registry

    def _check_keydescriptor(self, val):
        signing = [key for key in val if key.get('attrs', {}).get('use') == 'signing']
        if len(signing) == 0:
            raise Invalid('Deve essere presente almeno una chiave con attributo use uguale a "signing"')
        return val

    def validate(self, metadata):
        data = saml_to_dict(metadata)
        key_descriptor = Schema(
            All(
                [{
                    'attrs': Schema({
                        'use': All(str, In(
                            KEYDESCRIPTOR_USES,
                            msg=DEFAULT_LIST_VALUE_ERROR.format(', '.join(KEYDESCRIPTOR_USES)))
                        ),
                    }, required=True),
                    'children': {
                        '{%s}KeyInfo' % (SIGNATURE): {
                            'attrs': {},
                            'children': {
                                '{%s}X509Data' % (SIGNATURE): {
                                    'attrs': {},
                                    'children': {
                                        '{%s}X509Certificate' % (SIGNATURE): {
                                            'attrs': {},
                                            'children': {},
                                            'text': All(str, _check_certificate)
                                        }
                                    },
                                    'text': None
                                }
                            },
                            'text': None
                        }
                    },
                    'text': None
                }], self._check_keydescriptor),
            required=True,
        )
        slo = Schema(
            All(
                [{
                    'attrs': dict,
                    'children': dict,
                    'text': None
                }], Length(min=1)),
            required=True,
        )
        acs = Schema(
            All(
                [{
                    'attrs': dict,
                    'children': dict,
                    'text': None
                }], Length(min=1)),
            required=True,
        )
        atcs = Schema(
            All(
                [{
                    'attrs': {
                        'index': str
                    },
                    'children': {
                        '{%s}ServiceName' % (METADATA): {
                            'attrs': dict,
                            'children': {},
                            'text': str
                        },
                        Optional('{%s}ServiceDescription' % (METADATA)): {
                            'attrs': dict,
                            'children': {},
                            'text': str
                        },
                        '{%s}RequestedAttribute' % (METADATA): All(
                            [{
                                'attrs': {
                                    'Name': All(str, In(SPID_ATTRIBUTES_NAMES, msg=DEFAULT_LIST_VALUE_ERROR.format(', '.join(SPID_ATTRIBUTES_NAMES)))),
                                    Optional('NameFormat'): Equal(
                                        NAME_FORMAT_BASIC, msg=DEFAULT_VALUE_ERROR.format(
                                            NAME_FORMAT_BASIC)
                                    ),
                                    Optional('FriendlyName'): str,
                                    Optional('isRequired'): str
                                },
                                'children': {},
                                'text': None
                            }],
                            Length(min=1)),
                    },
                    'text': None
                }], Length(min=1)),
            required=True,
        )
        name_id_format = Schema(
            {
                'attrs': {},
                'children': {},
                'text': Equal(
                    NAMEID_FORMAT_TRANSIENT, msg=DEFAULT_VALUE_ERROR.format(
                        NAMEID_FORMAT_TRANSIENT)
                ),
            },
            required=True,
        )
        spsso_descriptor_attr_schema = Schema(
            All(
                {
                    'protocolSupportEnumeration': Equal(PROTOCOL, msg=DEFAULT_VALUE_ERROR.format(PROTOCOL)),
                    'AuthnRequestsSigned': Equal('true', msg=DEFAULT_VALUE_ERROR.format('true')),
                    Optional('WantAssertionsSigned'): str,

                }
            ),
            required=True
        )
        spsso = Schema(
            {
                'attrs': spsso_descriptor_attr_schema,
                'children': {
                    '{%s}KeyDescriptor' % (METADATA): key_descriptor,
                    '{%s}SingleLogoutService' % (METADATA): slo,
                    '{%s}AssertionConsumerService' % (METADATA): acs,
                    '{%s}AttributeConsumingService' % (METADATA): atcs,
                    '{%s}NameIDFormat' % (METADATA): name_id_format,
                },
                'text': None
            },
            required=True
        )
        entity_descriptor_schema = Schema({
            '{%s}EntityDescriptor' % (METADATA): {
                'attrs': Schema({
                    'entityID': str,
                    Optional('ID'): str,
                    Optional('validUntil'): All(str, _check_utc_date),
                    Optional('cacheDuration'): str,
                    Optional('Name'): str,
                }, required=True),
                'children': Schema(
                    {
                        Optional('{%s}Signature' % (SIGNATURE)): Schema(
                            {
                                'attrs': dict,
                                'children': dict,
                                'text': None
                            },
                            required=True,
                        ),
                        '{%s}SPSSODescriptor' % (METADATA): spsso,
                        Optional('{%s}Organization' % (METADATA)): dict,
                        Optional('{%s}ContactPerson' % (METADATA)): list
                    },
                    required=True
                ),
                'text': None
            }
        }, required=True)
        errors = []
        try:
            entity_descriptor_schema(data)
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

                        # strip namespaces for better readability
                        _paths.append(_strip_namespaces(str(_path)))
                path = '/'.join(_paths)
                if _attr is not None:
                    path = '{} - attribute: {}'.format(path, _attr)
                for _ in err.path:
                    try:
                        _val = _val[_]
                    except IndexError:
                        _val = None
                    except KeyError:
                        _val = None
                errors.append(
                    ValidationDetail(
                        _val, None, None, None, None, err.msg, path
                    )
                )
            raise SPIDValidationError(details=errors)


class SpidRequestValidator(object):

    def __init__(self, action, binding, registry=None, conf=None):
        self._action = action
        self._binding = binding
        self._config = conf or config.params
        if registry:  # FIXME fix circular import. this is ugly.
            self._registry = registry
        else:
            from testenv import spmetadata
            self._registry = spmetadata.registry

    def _check_date_in_range(self, date):
        date = str_to_datetime(date)
        now = datetime.utcnow()
        lower = now - timedelta(minutes=TIMEDELTA)
        upper = now + timedelta(minutes=TIMEDELTA)
        if date < lower or date > upper:
            raise Invalid(
                'Il valore non è compreso tra {} e {}'.format(
                    lower, upper
                )
            )
        return date

    def _check_date_not_expired(self, date):
        date = str_to_datetime(date)
        now = datetime.utcnow()
        if now >= date:
            raise Invalid('Richiesta scaduta in data {}'.format(date))
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
        try:
            sp_metadata = self._registry.get(issuer_name)
        except MetadataNotFoundError:
            raise UnknownEntityIDError(
                'L\'entity ID "{}" indicato nell\'elemento <Issuer> non corrisponde a nessun Service Provider registrato in questo Identity Provider di test.'.format(issuer_name)
            )

        atcss = sp_metadata.attribute_consuming_services
        attribute_consuming_service_indexes = [
            str(
                el.get('attrs').get('index')
            ) for el in atcss if 'index' in el.get('attrs', {})
        ]
        ascss = sp_metadata.assertion_consumer_services
        assertion_consumer_service_indexes = [
            str(el.get('index')) for el in ascss]
        assertion_consumer_service_urls = [
            str(el.get('Location')) for el in ascss]

        entity_id = self._config.entity_id

        issuer = Schema(
            {
                'attrs': {
                    'Format': Equal(
                        NAMEID_FORMAT_ENTITY, msg=DEFAULT_VALUE_ERROR.format(
                            NAMEID_FORMAT_ENTITY)
                    ),
                    'NameQualifier': Any(
                        Url(), Match(r'^urn:'), msg="Invalid URI"
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
                        NAMEID_FORMAT_TRANSIENT, msg=DEFAULT_VALUE_ERROR.format(
                            NAMEID_FORMAT_TRANSIENT)
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
                        NAMEID_FORMAT_TRANSIENT, msg=DEFAULT_VALUE_ERROR.format(
                            NAMEID_FORMAT_TRANSIENT)
                    ),
                    Optional('SPNameQualifier'): str,
                },
                'children': {},
                'text': None,
            },
            required=True,
        )

        conditions = Schema(
            {
                'attrs': {
                    'NotBefore': All(str, _check_utc_date),
                    'NotOnOrAfter': All(str, _check_utc_date),
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
                'text': All(str, In(SPID_LEVELS, msg=DEFAULT_LIST_VALUE_ERROR.format(', '.join(SPID_LEVELS))))
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
                        NAMEID_FORMAT_ENTITY, msg=DEFAULT_VALUE_ERROR.format(
                            NAMEID_FORMAT_ENTITY)
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
                'AssertionConsumerServiceURL' in keys and 'ProtocolBinding' in keys and 'AssertionConsumerServiceIndex' not in keys
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
                'AssertionConsumerServiceURL' not in keys and 'ProtocolBinding' not in keys and 'AssertionConsumerServiceIndex' in keys
            ):
                if attrs['AssertionConsumerServiceIndex'] not in assertion_consumer_service_indexes:
                    raise Invalid(
                        DEFAULT_LIST_VALUE_ERROR.format(
                            ', '.join(assertion_consumer_service_indexes)),
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
                    'IssueInstant': All(str, _check_utc_date, self._check_date_in_range),
                    'Destination': In(
                        [entity_id, self._config.absolute_sso_url],
                        msg=DEFAULT_VALUE_ERROR.format(entity_id)
                    ),
                    Optional('ForceAuthn'): str,
                    Optional('AttributeConsumingServiceIndex'): In(
                        attribute_consuming_service_indexes,
                        msg=DEFAULT_LIST_VALUE_ERROR.format(
                            ', '.join(attribute_consuming_service_indexes))
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
                    'IssueInstant': All(str, _check_utc_date, self._check_date_in_range),
                    'Destination': In(
                        [entity_id, self._config.absolute_sso_url],
                        msg=DEFAULT_VALUE_ERROR.format(entity_id)
                    ),
                    Optional('NotOnOrAfter'): All(str, _check_utc_date, self._check_date_not_expired),
                    Optional('Reason'): str,
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
                        '{%s}Signature' % (SIGNATURE): signature
                    }
                )
                authnrequest_schema[AUTHNREQUEST_TAG][
                    'children'] = _new_sub_schema
            if self._action == 'logout':
                _new_sub_schema = logoutrequest_schema[
                    LOGOUTREQUEST_TAG
                ]['children'].extend(
                    {
                        '{%s}Signature' % (SIGNATURE): signature
                    }
                )
                logoutrequest_schema[LOGOUTREQUEST_TAG][
                    'children'] = _new_sub_schema

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

                        # strip namespaces for better readability
                        _paths.append(_strip_namespaces(str(_path)))
                path = '/'.join(_paths)
                if _attr is not None:
                    path += " - attribute: " + _attr

                # find value to show (iterate multiple times inside data
                # until we find the sub-element or attribute)
                _val = data
                for _ in err.path:
                    try:
                        _val = _val[_]
                    except KeyError:
                        _val = None
                    except ValueError:
                        _val = None

                # no need to show value if the error is the presence of the element
                _msg = err.msg
                if "extra keys not allowed" in _msg:
                    _val = None
                    _msg = "item not allowed"

                errors.append(
                    ValidationDetail(
                        _val, None, None, None, None, _msg, path
                    )
                )
            raise SPIDValidationError(details=errors)
