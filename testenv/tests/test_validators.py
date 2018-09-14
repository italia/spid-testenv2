# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

import pytest
from freezegun import freeze_time

from testenv import settings
from testenv.exceptions import SPIDValidationError, XMLFormatValidationError, XMLSchemaValidationError
from testenv.tests.data import sample_saml_requests as sample_requests
from testenv.tests.utils import FakeRequest
from testenv.validators import AuthnRequestXMLSchemaValidator, SpidValidator, XMLFormatValidator


class FakeTranslator(object):

    def translate_many(self, errors):
        return errors


class FakeConfig(object):
    def __init__(self, endpoint, entity_id):
        self._endpoint = endpoint
        self._entity_id = entity_id

    def receivers(self, *args, **kwargs):
        return [self._endpoint]

    @property
    def entity_id(self, *args, **kwargs):
        return self._entity_id


class FakeMetadata(dict):
    def __init__(self, service_providers):
        self._service_providers = service_providers

    def service_providers(self):
        return self._service_providers


class XMLFormatValidatorTestCase(unittest.TestCase):

    def test_valid_request(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest('<a></a>')
        self.assertIsNone(validator.validate(request))

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


class SPIDValidatorTestCase(unittest.TestCase):

    maxDiff = None

    @freeze_time('2018-08-18T06:55:22Z')
    def test_missing_issuer(self):
        # https://github.com/italia/spid-testenv2/issues/133
        config = FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        for binding, val in {settings.BINDING_HTTP_POST: sample_requests.fake_signature, settings.BINDING_HTTP_REDIRECT: ''}.items():
            request = FakeRequest(sample_requests.missing_issuer)
            validator = SpidValidator('login', binding, {}, config)
            with pytest.raises(SPIDValidationError) as excinfo:
                request.saml_request = request.saml_request % (val)
                validator.validate(request)
            exc = excinfo.value
            self.assertEqual('required key not provided', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_wrong_destination(self):
        # https://github.com/italia/spid-testenv2/issues/158
        config = FakeConfig('http://localhost:9999/sso', 'http://localhost:9999/')
        metadata = FakeMetadata(['https://localhost:8088/'])
        for binding, val in {settings.BINDING_HTTP_POST: sample_requests.fake_signature, settings.BINDING_HTTP_REDIRECT: ''}.items():
            validator = SpidValidator('login', binding, metadata, config)
            request = FakeRequest(sample_requests.wrong_destination)
            with pytest.raises(SPIDValidationError) as excinfo:
                request.saml_request = request.saml_request % (val)
                validator.validate(request)
            exc = excinfo.value
            self.assertEqual('è diverso dal valore di riferimento http://localhost:9999/', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_http_post_without_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        request = FakeRequest(sample_requests.no_signature % (''))
        metadata = FakeMetadata(['https://localhost:8088/'])
        validator = SpidValidator('login', settings.BINDING_HTTP_POST, metadata, config)
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(
            'xpath: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest/{http://www.w3.org/2000/09/xmldsig#}Signature',
            exc.details[0].path
        )
        self.assertEqual('required key not provided', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_http_post_with_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        request = FakeRequest(sample_requests.no_signature % (sample_requests.fake_signature))
        metadata = FakeMetadata(['https://localhost:8088/'])
        validator = SpidValidator('login', settings.BINDING_HTTP_POST, metadata, config)
        validator.validate(request)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_http_redirect_with_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        request = FakeRequest(sample_requests.no_signature % (sample_requests.fake_signature))
        metadata = FakeMetadata(['https://localhost:8088/'])
        validator = SpidValidator('login', settings.BINDING_HTTP_REDIRECT, metadata, config)
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(
            'xpath: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest/{http://www.w3.org/2000/09/xmldsig#}Signature',
            exc.details[0].path
        )
        self.assertEqual('extra keys not allowed', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_http_redirect_without_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        request = FakeRequest(sample_requests.no_signature % (''))
        metadata = FakeMetadata(['https://localhost:8088/'])
        validator = SpidValidator('login', settings.BINDING_HTTP_REDIRECT, metadata, config)
        validator.validate(request)
