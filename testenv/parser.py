# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from datetime import datetime, timedelta
from functools import reduce

from lxml import etree

import importlib_resources
from flask import escape
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.saml import NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_TRANSIENT
from testenv.settings import COMPARISONS, SPID_LEVELS, TIMEDELTA, XML_SCHEMAS
from testenv.spid import Observer
from testenv.translation import Libxml2Translator
from testenv.utils import XMLError, check_url, check_utc_date, str_to_time


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
            issuer = kwargs.get('issuer')
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
                            Attr('name_qualifier', default=issuer, func=check_url),
                            Attr('text', func=check_url)
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
                    Attr('destination', default=receivers),
                ],
                children=[
                    Elem(
                        'issuer',
                        tag='saml:Issuer',
                        attributes=[
                            Attr('format', default=NAMEID_FORMAT_ENTITY),
                            Attr('name_qualifier', default=issuer, func=check_url),
                            Attr('text', func=check_url)
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
            errors['validation_errors'] = validation_error
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


class XMLSchemaFileLoader(object):
    """
    Load XML Schema instances from the filesystem.
    """

    def __init__(self, import_path=None):
        self._import_path = import_path or 'testenv.xsd'

    def load(self, name):
        with importlib_resources.path(self._import_path, name) as path:
            xmlschema_doc = etree.parse(str(path))
            return etree.XMLSchema(xmlschema_doc)


class XMLValidator(object):
    """
    Validate XML fragments against XML Schema (XSD).
    """

    def __init__(self, schema_loader=None, parser=None, translator=None):
        self._schema_loader = schema_loader or XMLSchemaFileLoader()
        self._parser = parser or etree.XMLParser()
        self._translator = translator or Libxml2Translator()
        self._load_schemas()

    def _load_schemas(self):
        self._schemas = {
            type_: self._schema_loader.load(name)
            for type_, name in XML_SCHEMAS.items()
        }

    def validate_request(self, xml):
        return self._run(xml, 'protocol')

    def _run(self, xml, schema_type):
        xml_doc, parsing_errors = self._parse_xml(xml)
        if parsing_errors:
            return parsing_errors
        return self._validate_xml(xml_doc, schema_type)

    def _parse_xml(self, xml):
        xml_doc, errors = None, []
        try:
            xml_doc = etree.fromstring(xml, parser=self._parser)
        except SyntaxError:
            error_log = self._parser.error_log
            errors = self._handle_errors(error_log)
        return xml_doc, errors

    def _validate_xml(self, xml_doc, schema_type):
        schema = self._schemas[schema_type]
        errors = []
        try:
            schema.assertValid(xml_doc)
        except Exception:
            error_log = schema.error_log
            errors = self._handle_errors(error_log)
        return errors

    def _handle_errors(self, errors):
        original_errors = [
            XMLError(err.line, err.column, err.domain_name,
                     err.type_name, err.message, err.path)
            for err in errors
        ]
        return self._translator.translate_many(original_errors)
