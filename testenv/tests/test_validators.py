# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

import pytest

from testenv.exceptions import XMLFormatValidationError, XMLSchemaValidationError
from testenv.validators import AuthnRequestXMLSchemaValidator, XMLFormatValidator
from testenv.tests.data import sample_saml_requests as sample_requests
from testenv.tests.utils import FakeRequest


class FakeTranslator(object):

    def translate_many(self, errors):
        return errors


class XMLFormatValidatorTestCase(unittest.TestCase):

    def test_empty_request(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest('')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn('Document is empty', exc.details[0].message)

    def test_not_xml(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest('{"this": "is JSON"}')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn(
            "Start tag expected, '<' not found", exc.details[0].message)

    def test_tag_mismatch(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest('<a></b>')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn(
            'Opening and ending tag mismatch: a line 1 and b',
            exc.details[0].message
        )

    def test_duplicate_attribute(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest('<a attr="value" attr="value"></a>')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn('Attribute attr redefined', exc.details[0].message)


class AuthnRequestXMLSchemaValidatorTestCase(unittest.TestCase):

    def test_valid_requests(self):
        validator = AuthnRequestXMLSchemaValidator(translator=FakeTranslator())
        for request in sample_requests.valid:
            request = FakeRequest(request)
            self.assertIsNone(validator.validate(request))

    def test_invalid_attribute_format(self):
        # See: https://github.com/italia/spid-testenv2/issues/63
        validator = AuthnRequestXMLSchemaValidator(translator=FakeTranslator())
        request = FakeRequest(sample_requests.invalid_id_attr)
        with pytest.raises(XMLSchemaValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn(
            "is not a valid value of the atomic type 'xs:ID'",
            exc.details[0].message
        )

    def test_missing_mandatory_attribute(self):
        validator = AuthnRequestXMLSchemaValidator(translator=FakeTranslator())
        request = FakeRequest(sample_requests.missing_issue_instant_attr)
        with pytest.raises(XMLSchemaValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn(
            "The attribute 'IssueInstant' is required but missing.",
            exc.details[0].message
        )

    def test_multiple_errors(self):
        validator = AuthnRequestXMLSchemaValidator(translator=FakeTranslator())
        request = FakeRequest(sample_requests.multiple_errors)
        with pytest.raises(XMLSchemaValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 2)
        self.assertIn(
            "is not a valid value of the atomic type 'xs:ID'",
            exc.details[0].message
        )
        self.assertIn(
            "The attribute 'Version' is required but missing.",
            exc.details[1].message
        )

    def test_unexpected_element(self):
        # See: https://github.com/italia/spid-testenv2/issues/79
        validator = AuthnRequestXMLSchemaValidator(translator=FakeTranslator())
        request = FakeRequest(sample_requests.unexpected_element)
        with pytest.raises(XMLSchemaValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn(
            "Element '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef': "
            "This element is not expected. Expected is one of ( {urn:oasis:names:tc:SAML:2.0:assertion}"
            "Conditions, {urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext, {urn:oasis:names:tc:SAML:2.0:protocol}Scoping ).",
            exc.details[0].message
        )

    def test_invalid_comparison_attribute(self):
        # https://github.com/italia/spid-testenv2/issues/97
        validator = AuthnRequestXMLSchemaValidator(translator=FakeTranslator())
        request = FakeRequest(sample_requests.invalid_comparison_attr)
        with pytest.raises(XMLSchemaValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 2)
        self.assertIn(
            "The value 'invalid' is not an element of the set "
            "{'exact', 'minimum', 'maximum', 'better'}",
            exc.details[0].message
        )
        self.assertIn(
            "'invalid' is not a valid value of the atomic type",
            exc.details[1].message
        )
