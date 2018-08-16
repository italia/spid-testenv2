# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import zlib
from base64 import b64decode
from collections import namedtuple
from datetime import datetime, timedelta
from functools import reduce

from flask import escape
from lxml import etree, objectify
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.saml import NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_TRANSIENT

from testenv.exceptions import (DeserializationError, RequestParserError,
                                StopValidation, ValidationError,
                                XMLFormatValidationError)
from testenv.settings import COMPARISONS, SPID_LEVELS, TIMEDELTA
from testenv.spid import Observer
from testenv.utils import SPIDError, check_utc_date, saml_to_dict, str_to_time


def validate_request(xmlstr, action, binding, **kwargs):

    MANDATORY_ERROR = 'L\'attributo è obbligatorio'
    NO_WANT_ERROR = 'L\'attributo non è richiesto'
    DEFAULT_VALUE_ERROR = 'è diverso dal valore di riferimento {}'
    DEFAULT_LIST_VALUE_ERROR = 'non corrisponde a nessuno'\
    ' dei valori contenuti in {}'
    ASSERTION = '{urn:oasis:names:tc:SAML:2.0:assertion}'
    PROTOCOL = '{urn:oasis:names:tc:SAML:2.0:protocol}'
    SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#'

    from voluptuous import Schema, In, MultipleInvalid, ALLOW_EXTRA
    from voluptuous import Optional, All, Invalid
    from voluptuous.validators import Equal
    from saml2 import time_util

    def _check_utc_date(date):
        try:
            time_util.str_to_time(date)
        except Exception as e:
            print(e)
            raise Invalid('la data non è in formato UTC')
        return date

    def _check_date_in_range(date):
        date = str_to_time(date)
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

    attribute_consuming_service_indexes = kwargs.get(
        'attribute_consuming_service_indexes'
    )
    assertion_consumer_service_indexes = kwargs.get(
        'assertion_consumer_service_indexes'
    )
    receivers = kwargs.get('receivers')
    issuer = kwargs.get('issuer')

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
            Optional('AllowCreate'): Equal('true', msg=DEFAULT_VALUE_ERROR.format('true'))
        },
        'children': {},
        'text': None,
        },
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
                'IssueInstant': All(str, _check_utc_date, _check_date_in_range),
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

    if binding == BINDING_HTTP_POST:
        authnrequest_schema['children']['{}Signature'.format(SIGNATURE)]

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
                'IssueInstant': All(str, _check_utc_date, _check_date_in_range),
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
    if action == 'login':
        saml_schema = authn_request
    elif action == 'logout':
        saml_schema = logout_request
    data = saml_to_dict(xmlstr)
    errors = []
    try:
        saml_schema(data)
    except MultipleInvalid as e:
        for err in e.errors:
            _val = data
            for _ in err.path:
                _val = _val.get(_)
            errors.append(
                SPIDError(
                    _val, err.msg, err.path
                )
            )
    return errors


class Attr(object):
    """
    Define an attribute for a SAML2 element
    """

    MANDATORY_ERROR = 'L\'attributo è obbligatorio'
    NO_WANT_ERROR = 'L\'attributo non è richiesto'
    DEFAULT_VALUE_ERROR = '{} è diverso dal valore di riferimento {}'
    DEFAULT_LIST_VALUE_ERROR = '{} non corrisponde a nessuno'\
    ' dei valori contenuti in {}'
    LIMITS_VALUE_ERROR = '{} non è compreso tra {} e {}'

    def __init__(
        self, name, absent=False, required=True, default=None, limits=None,
        func=None, val_converter=None, *args, **kwargs
    ):
        """
        :param name: attribute name
        :param absent: flag to indicate if the attribute
            is not allowed (False by default)
        :param required: flag to indicate if the attribute
            is mandatory (True by default)
        :param default: default value (or list of values,
            to be compared with the provided value to the 'validate' method)
        :param limits: tuple containing lower limit and upper limit
        :param func: optional additional function to perform
            a validation on the value passed to 'validate' method
        :param val_converter: optional additional function to perform
            a conversion on the value passed to 'validate' method
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
                if isinstance(self._default, list) and\
                 value not in self._default:
                    val_error = self.DEFAULT_LIST_VALUE_ERROR.format(
                        value,
                        self._default
                    )
                    self._errors['value_error'] = val_error
                elif isinstance(self._default, str) and self._default != value:
                    val_error = self.DEFAULT_VALUE_ERROR.format(
                        value, self._default
                    )
                    self._errors['value_error'] = val_error
            if self._limits is not None and value is not None:
                if self._val_converter:
                    value = self._val_converter(value)
                lower, upper = self._limits
                if value > upper or value < lower:
                    err_msg = self.LIMITS_VALUE_ERROR
                    self._errors['limits_error'] = err_msg.format(
                        value, lower, upper
                    )
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


class MultiAttr(object):
    def __init__(self, *attrs):
        self._attrs = []
        for attr in attrs:
            self._attrs.append(attr)

    @property
    def real_name(self):
        return '[{}]'.format(', '.join([attr.real_name for attr in self._attrs]))


class And(MultiAttr):

    def validate(self, obj):
        _validations = {}
        _validations_secondary = {}
        _errors = {}
        _validation_matrix = []
        for attr in self._attrs:
            if isinstance(attr, MultiAttr):
                _vals, _err = attr.validate(obj)
                _validations_secondary.update(_vals)
                if not _err:
                    _validation_matrix.append(True)
                else:
                    _validation_matrix.append(False)
            else:
                _elem = getattr(obj, attr._name)
                _validations[attr.real_name] = attr.validate(_elem)
                if _elem is not None:
                    _validation_matrix.append(True)
                else:
                    _validation_matrix.append(False)
        _reduced = reduce((lambda x, y: x or y), _validation_matrix)
        if not all(_validation_matrix) and not _reduced:
            error_msg = 'Tutti gli attributi o gruppi di attributi' \
            ' devono essere presenti: [{}]'
            _errors['required_error'] = error_msg.format(
                ', '.join([a.real_name for a in self._attrs])
            )
        _validations.update(_validations_secondary)
        return _validations, _errors


class Or(MultiAttr):

    def validate(self, obj):
        _validations = {}
        _validations_secondary = {}
        _errors = {}
        _validation_matrix = []
        for attr in self._attrs:
            if isinstance(attr, MultiAttr):
                _vals, _err = attr.validate(obj)
                _validations_secondary.update(_vals)
                if not _err:
                    _validation_matrix.append(True)
                else:
                    _validation_matrix.append(False)
            else:
                _elem = getattr(obj, attr._name)
                _validations[attr.real_name] = attr.validate(_elem)
                if _elem is not None:
                    _validation_matrix.append(True)
                else:
                    _validation_matrix.append(False)
        if not reduce((lambda x, y: x ^ y), _validation_matrix):
            error_msg = 'Uno e uno solo uno tra gli attributi o' \
            ' gruppi di attributi devono essere presenti: [{}]'
            _errors['required_error'] = error_msg.format(
                ', '.join([a.real_name for a in self._attrs])
            )
        _validations.update(_validations_secondary)
        return _validations, _errors


class TimestampAttr(Attr):

    RANGE_TIME_ERROR = '{} non è compreso tra {} e {}'

    def validate(self, value=None):
        validation = super(TimestampAttr, self).validate(value)
        value = self._val_converter(value)
        now = datetime.utcnow()
        lower = now - timedelta(minutes=TIMEDELTA)
        upper = now + timedelta(minutes=TIMEDELTA)
        if value < lower or value > upper:
            error_msg = self.RANGE_TIME_ERROR.format(
                value, lower, upper
            )
            validation['errors']['range_time_error'] = error_msg
        return validation


class Elem(object):
    """
    Define a SAML2 element
    """

    MANDATORY_ERROR = 'L\'elemento è obbligatorio'
    NO_WANT_ERROR = 'L\'elemento non è richiesto'

    def __init__(
        self, name, tag, absent=False, required=True, attributes=[],
        children=[], example='', *args, **kwargs
    ):
        """
        :param name: element name
        :param tag: element 'namespace:tag_name'
        :param required: flag to indicate if the element
            is mandatory (True by default)
        :param attributes: list of Attr objects (element attributes)
        :param children: list of Elem objects (nested elements)
        :param example: string to explain
            how the missing element need to be implemented
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
        res = {'attrs': {}, 'children': {}, 'errors': {}}
        if self._absent and data is not None:
            res['errors']['no_want_error'] = self.NO_WANT_ERROR
            self._errors.update(res['errors'])
        else:
            if self._required and data is None:
                # check if the element is required, if not provide and example
                _error_msg = self.MANDATORY_ERROR
                if self._example:
                    _example = '<br>Esempio:<br>'
                    lines = self._example.splitlines()
                    for line in lines:
                        _example = '{}<pre>{}</pre>'.format(_example, escape(line))
                else:
                    _example = ''
                _error_msg = '{} {}'.format(_error_msg, _example)
                res['errors']['required_error'] = _error_msg
                self._errors.update(res['errors'])
            if data:
                if isinstance(data, list):
                    # TODO: handle list elements in a clean way
                    data = data[0]
                for attribute in self._attributes:
                    if isinstance(attribute, MultiAttr):
                        _validations, _err = attribute.validate(data)
                        for k, v in _validations.items():
                            if v['errors']:
                                self._errors.update({k: v['errors']})
                        res['attrs'].update(_validations)
                        if _err:
                            res['errors']['multi_attribute_error'] = _err
                            self._errors.update(res['errors'])
                    else:
                        _validated_attributes = attribute.validate(
                            getattr(data, attribute._name)
                        )
                        attr_real_name = attribute.real_name
                        res['attrs'][attr_real_name] = _validated_attributes
                        if _validated_attributes['errors']:
                            _validation_errors = {
                                attr_real_name: _validated_attributes['errors']
                            }
                            self._errors.update(
                                _validation_errors
                            )
                for child in self._children:
                    res['children'][child._name] = child.validate(
                        getattr(data, child._name)
                    )
        return res


class SpidParser(object):
    """
    Parser for spid messages
    """

    def __init__(self, *args, **kwargs):
        from testenv.parser import XMLValidator
        self.xml_validator = XMLValidator()
        self.schema = None

    def get_schema(self, action, binding, **kwargs):
        """
        :param binding:
        """
        _schema = None
        receivers = kwargs.get('receivers')
        issuer = kwargs.get('issuer')
        if action == 'login':
            required_signature = False
            if binding == BINDING_HTTP_POST:
                required_signature = True
            elif binding == BINDING_HTTP_REDIRECT:
                required_signature = False
            attribute_consuming_service_indexes = kwargs.get(
                'attribute_consuming_service_indexes'
            )
            assertion_consumer_service_indexes = kwargs.get(
                'assertion_consumer_service_indexes'
            )
            _schema = Elem(
                name='auth_request',
                tag='samlp:AuthnRequest',
                attributes=[
                    Attr('id'),
                    Attr('version', default='2.0'),
                    TimestampAttr(
                        'issue_instant',
                        func=check_utc_date,
                        val_converter=str_to_time
                    ),
                    Attr('destination', default=receivers),
                    Attr('force_authn', required=False),
                    Attr(
                        'attribute_consuming_service_index',
                        default=attribute_consuming_service_indexes,
                        required=False
                    ),
                    Or(
                        Attr(
                            'assertion_consumer_service_index',
                            default=assertion_consumer_service_indexes,
                            required=False
                        ),
                        And(
                            Attr(
                                'assertion_consumer_service_url',
                                required=False
                            ),
                            Attr(
                                'protocol_binding',
                                default=BINDING_HTTP_POST,
                                required=False
                            )
                        )
                    )
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
                        attributes=[
                            Attr('format', default=NAMEID_FORMAT_ENTITY),
                            Attr('name_qualifier', default=issuer),
                            Attr('text', default=issuer)
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
                        tag='saml:RequestedAuthnContext',
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
                    Attr('destination', default=receivers),
                ],
                children=[
                    Elem(
                        'issuer',
                        tag='saml:Issuer',
                        attributes=[
                            Attr('format', default=NAMEID_FORMAT_ENTITY),
                            Attr('name_qualifier', default=issuer),
                            Attr('text', default=issuer)
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

        errors = {}
        # Validate xml against its XSD schema
        validation_errors = self.xml_validator.validate_request(obj.xmlstr)
        if validation_errors:
            errors['validation_errors'] = validation_errors
        # Validate xml against SPID rules
        _schema = self.get_schema(action, binding, **kwargs)\
            if schema is None else schema
        self.observer = Observer()
        self.observer.attach(_schema)
        validated = _schema.validate(obj.message)
        spid_errors = self.observer.evaluate()
        if spid_errors:
            errors['spid_errors'] = spid_errors
        return validated, errors


HTTPRedirectRequest = namedtuple(
    'HTTPRedirectRequest',
    ['saml_request', 'sig_alg', 'signature'],
)


HTTPPostRequest = namedtuple('HTTPPostRequest', ['saml_request'])


class HTTPRedirectRequestParser(object):
    def __init__(self, querystring, request_class=None):
        self._querystring = querystring
        self._request_class = request_class or HTTPRedirectRequest
        self._saml_request = None
        self._sig_alg = None
        self._signature = None

    def parse(self):
        self._saml_request = self._parse_saml_request()
        self._sig_alg = self._parse_sig_alg()
        self._signature = self._parse_signature()
        return self._build_request()

    def _parse_saml_request(self):
        saml_request = self._extract('SAMLRequest')
        return self._decode_saml_request(saml_request)

    def _extract(self, key):
        try:
            return self._querystring[key]
        except KeyError as e:
            self._fail("Dato mancante nella request: '{}'".format(e.args[0]))

    @staticmethod
    def _fail(message):
        raise RequestParserError(message)

    def _decode_saml_request(self, saml_request):
        try:
            return self._convert_saml_request(saml_request)
        except Exception:  # FIXME detail exceptions
            self._fail("Impossibile decodificare l'elemento 'SAMLRequest'")

    @staticmethod
    def _convert_saml_request(saml_request):
        saml_request = b64decode(saml_request)
        saml_request = zlib.decompress(saml_request, -15)
        return saml_request.decode()

    def _parse_sig_alg(self):
        return self._extract('SigAlg')

    def _parse_signature(self):
        signature = self._extract('Signature')
        return self._decode_signature(signature)

    def _decode_signature(self, signature):
        try:
            return b64decode(signature)
        except Exception:
            self._fail("Impossibile decodificare l'elemento 'Signature'")

    def _build_request(self):
        return self._request_class(
            self._saml_request,
            self._sig_alg,
            self._signature,
        )


class HTTPPostRequestParser(object):
    def __init__(self, form, request_class=None):
        self._form = form
        self._request_class = request_class or HTTPPostRequest
        self._saml_request = None

    def parse(self):
        self._saml_request = self._parse_saml_request()
        return self._build_request()

    def _parse_saml_request(self):
        saml_request = self._extract('SAMLRequest')
        return self._decode_saml_request(saml_request)

    def _extract(self, key):
        try:
            return self._form[key]
        except KeyError as e:
            self._fail("Dato mancante nella request: '{}'".format(e.args[0]))

    @staticmethod
    def _fail(message):
        raise RequestParserError(message)

    def _decode_saml_request(self, saml_request):
        try:
            return self._convert_saml_request(saml_request)
        except Exception:  # FIXME detail exceptions
            self._fail("Impossibile decodificare l'elemento 'SAMLRequest'")

    @staticmethod
    def _convert_saml_request(saml_request):
        saml_request = b64decode(saml_request)
        return saml_request.decode()

    def _build_request(self):
        return self._request_class(self._saml_request)


class HTTPRequestDeserializer(object):
    _validators = []

    def __init__(self, request, saml_class=None):
        self._request = request
        self._saml_class = saml_class or SAMLTree
        self._validation_errors = []

    def deserialize(self):
        self._validate()
        if self._validation_errors:
            raise DeserializationError(self._validation_errors)
        return self._deserialize()

    def _validate(self):
        try:
            self._run_validators()
        except StopValidation:
            pass

    def _run_validators(self):
        for validator in self._validators:
            self._run_validator(validator)

    def _run_validator(self, validator):
        try:
            validator.validate(self._request)
        except XMLFormatValidationError as e:
            self._handle_blocking_error(e)
        except ValidationError as e:
            self._handle_nonblocking_error(e)

    def _handle_blocking_error(self, error):
        self._handle_nonblocking_error(error)
        raise StopValidation

    def _handle_nonblocking_error(self, error):
        self._validation_errors += error.details

    def _deserialize(self):
        xml_doc = objectify.fromstring(self._request.saml_request)
        return self._saml_class(xml_doc)


class SAMLTree(object):
    def __init__(self, xml_doc):
        self._xml_doc = xml_doc
        self._bind_tag()
        self._bind_attributes()
        self._bind_text()
        self._bind_subtrees()

    def _bind_tag(self):
        self.tag = etree.QName(self._xml_doc).localname

    def _bind_attributes(self):
        for attr_name, attr_val in self._xml_doc.attrib.items():
            setattr(self, attr_name.lower(), attr_val)

    def _bind_text(self):
        self.text = self._xml_doc.text

    def _bind_subtrees(self):
        for child in self._xml_doc.iterchildren():
            child_name = etree.QName(child).localname.lower()
            subtree = SAMLTree(child)
            setattr(self, child_name, subtree)
