from collections import namedtuple

import importlib_resources
from lxml import etree

from testenv.exceptions import (XMLFormatValidationError,
                                XMLSchemaValidationError)
from testenv.settings import XML_SCHEMAS
from testenv.translation import Libxml2Translator
from testenv.utils import XMLError

Invalid = namedtuple(
    'Invalid',
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
            Invalid(None, err.line, err.column, err.domain_name,
                    err.type_name, err.message, err.path)
            for err in errors
        ]

    def _localize_messages(self, errors):
        return self._translator.translate_many(errors)


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
            Invalid(None, err.line, err.column, err.domain_name,
                    err.type_name, err.message, err.path)
            for err in error_log
        ]

    def _localize_messages(self, errors):
        return self._translator.translate_many(errors)


class AuthnRequestXMLSchemaValidator(BaseXMLSchemaValidator):
    def validate(self, request):
        xml = request.saml_request
        schema_type = 'protocol'  # FIXME
        return self._run(xml, schema_type)
