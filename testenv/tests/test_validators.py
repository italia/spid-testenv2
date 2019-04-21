# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

import pytest
from freezegun import freeze_time

from testenv import settings
from testenv.exceptions import (
    SPIDValidationError, UnknownEntityIDError, XMLFormatValidationError, XMLSchemaValidationError,
)
from testenv.saml import create_sp_metadata
from testenv.settings import BINDING_HTTP_POST
from testenv.tests.data import sample_saml_requests as sample_requests
from testenv.tests.utils import FakeRequest
from testenv.utils import Acs, Atcs, Key, Slo
from testenv.validators import (
    AuthnRequestXMLSchemaValidator, SpidMetadataValidator, SpidRequestValidator, XMLFormatValidator,
)

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


def fake_check_certificate(cert):
    return cert


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

    @property
    def absolute_sso_url(self):
        return self._endpoint

    @property
    def absolute_slo_url(self):
        return self._endpoint


class FakeMetadata(dict):

    def __init__(self, service_providers, assertion_consumer_services):
        self._service_providers = service_providers
        self._assertion_consumer_services = assertion_consumer_services

    def service_providers(self):
        return self._service_providers

    def assertion_consumer_service(self, assertion_consumer_service):
        return self._assertion_consumer_services


class FakeRegistry(object):

    def __init__(self, metadata):
        self._metadata = metadata.copy()

    def get(self, entity_id):
        return self._metadata.get(entity_id)

    @property
    def service_providers(self):
        return list(self._metadata.keys())


class ServiceProviderMetadataFakeLoader(object):

    def __init__(self, atcs_indexes, acs_indexes):
        self.atcs_indexes = atcs_indexes
        self.acs_indexes = acs_indexes

    @property
    def attribute_consuming_services(self):
        return [
            {'attrs': {'index': index}} for index in self.atcs_indexes
        ]

    @property
    def assertion_consumer_services(self):
        return [
            {'index': acs[0], 'Location': acs[1]} for acs in self.acs_indexes
        ]


class XMLFormatValidatorTestCase(unittest.TestCase):

    def test_valid_request(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest(b'<a></a>')
        self.assertIsNone(validator.validate(request))

    def test_empty_request(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest(b'')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn('Document is empty', exc.details[0].message)

    def test_not_xml(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest(b'{"this": "is JSON"}')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn(
            "Start tag expected, '<' not found", exc.details[0].message)

    def test_tag_mismatch(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest(b'<a></b>')
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
        request = FakeRequest(b'<a attr="value" attr="value"></a>')
        with pytest.raises(XMLFormatValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertIn('Attribute attr redefined', exc.details[0].message)

    def test_xml_with_declarations(self):
        validator = XMLFormatValidator(translator=FakeTranslator())
        request = FakeRequest(b'<?xml version="1.0" encoding="utf-8" ?><a></a>')
        validator.validate(request)


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
            "Element 'AuthnContextClassRef': "
            "This element is not expected. Expected is one of ( "
            "Conditions, RequestedAuthnContext, Scoping ).",
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


class SpidRequestValidatorTestCase(unittest.TestCase):

    maxDiff = None

    @freeze_time('2018-08-18T06:55:22Z')
    def test_missing_issuer(self):
        # https://github.com/italia/spid-testenv2/issues/133
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        registry = FakeRegistry({
            'http://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        for binding, val in {settings.BINDING_HTTP_POST: sample_requests.fake_signature, settings.BINDING_HTTP_REDIRECT: ''}.items():
            request = FakeRequest(sample_requests.missing_issuer)
            validator = SpidRequestValidator('login', binding, registry, config)
            with pytest.raises(UnknownEntityIDError) as excinfo:
                request.saml_request = request.saml_request % (val)
                validator.validate(request)
            exc = excinfo.value
            self.assertEqual(
                'Issuer non presente nella AuthnRequest', str(exc))

    @freeze_time('2018-08-18T06:55:22Z')
    def test_wrong_destination(self):
        # https://github.com/italia/spid-testenv2/issues/158
        config = FakeConfig('http://localhost:9999/sso',
                            'http://localhost:9999/')
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        for binding, val in {
            settings.BINDING_HTTP_POST: sample_requests.fake_signature,
            settings.BINDING_HTTP_REDIRECT: ''
        }.items():
            validator = SpidRequestValidator('login', binding, registry, config)
            request = FakeRequest(sample_requests.wrong_destination)
            with pytest.raises(SPIDValidationError) as excinfo:
                request.saml_request = request.saml_request % (val)
                validator.validate(request)
            exc = excinfo.value
            self.assertEqual(
                'Il valore dell\'elemento è diverso dal valore atteso (http://localhost:9999/):', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_authn_request_http_post_without_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.auth_no_signature % (''))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'login', settings.BINDING_HTTP_POST, registry, config)
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(
            'AuthnRequest/Signature',
            exc.details[0].path
        )
        self.assertEqual('required key not provided', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_authn_request_http_post_with_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.auth_no_signature %
                              (sample_requests.fake_signature))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'login', settings.BINDING_HTTP_POST, registry, config)
        validator.validate(request)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_authn_request_http_redirect_with_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.auth_no_signature %
                              (sample_requests.fake_signature))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'login', settings.BINDING_HTTP_REDIRECT, registry, config)
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(
            'AuthnRequest/Signature',
            exc.details[0].path
        )
        self.assertEqual('item not allowed', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_authn_request_http_redirect_without_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.auth_no_signature % (''))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'login', settings.BINDING_HTTP_REDIRECT, registry, config)
        validator.validate(request)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_logout_request_http_post_without_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.logout_no_signature % (''))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'logout', settings.BINDING_HTTP_POST, registry, config)
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(
            'LogoutRequest/Signature',
            exc.details[0].path
        )
        self.assertEqual('required key not provided', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_logout_request_http_post_with_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.logout_no_signature %
                              (sample_requests.fake_signature))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'logout', settings.BINDING_HTTP_POST, registry, config)
        validator.validate(request)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_logout_request_http_redirect_with_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.logout_no_signature %
                              (sample_requests.fake_signature))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'logout', settings.BINDING_HTTP_REDIRECT, registry, config)
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(request)
        exc = excinfo.value
        self.assertEqual(
            'LogoutRequest/Signature',
            exc.details[0].path
        )
        self.assertEqual('item not allowed', exc.details[0].message)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_logout_request_http_redirect_without_signature(self):
        # https://github.com/italia/spid-testenv2/issues/159
        # https://github.com/italia/spid-testenv2/issues/165
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.logout_no_signature % (''))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'logout', settings.BINDING_HTTP_REDIRECT, registry, config)
        validator.validate(request)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_logout_request_http_post_with_notonorafter_attr(self):
        # https://github.com/italia/spid-testenv2/issues/159
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.logout_with_notonorafter_attr %
                              (sample_requests.fake_signature))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'logout', settings.BINDING_HTTP_POST, registry, config)
        validator.validate(request)

    @freeze_time('2018-08-18T06:55:22Z')
    def test_logout_request_http_post_with_reason_attr(self):
        # https://github.com/italia/spid-testenv2/issues/159
        config = FakeConfig('http://localhost:8088/sso',
                            'http://localhost:8088/')
        request = FakeRequest(sample_requests.logout_with_reason_attr %
                              (sample_requests.fake_signature))
        registry = FakeRegistry({
            'https://localhost:8088/': ServiceProviderMetadataFakeLoader([], [(0, 'http://localhost:3000/spid-sso')])
        })
        validator = SpidRequestValidator(
            'logout', settings.BINDING_HTTP_POST, registry, config)
        validator.validate(request)


class SpidMetadataValidatorTestCase(unittest.TestCase):

    maxDiff = None

    @patch('testenv.validators._check_certificate', side_effect=fake_check_certificate)
    def test_valid_metadata(self, mocked):
        FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        validator = SpidMetadataValidator()
        metadata = create_sp_metadata(
            entity_id='http://test.sp',
            authn_request_signed='true',
            assertion_consumer_services=[Acs(location='http://test.sp/acs')],
            attribute_consuming_services=[
                Atcs(
                    service_name='test_1',
                    attributes=['spidCode']
                )
            ],
            single_logout_services=[
                Slo(binding=BINDING_HTTP_POST, location='http://test.sp/slo')
            ],
            keys=[Key('signing', 'somevalue123')]
        ).to_xml()
        validator.validate(metadata)

    @patch('testenv.validators._check_certificate', side_effect=fake_check_certificate)
    def test_missing_slo(self, mocked):
        FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        validator = SpidMetadataValidator()
        metadata = create_sp_metadata(
            entity_id='http://test.sp',
            authn_request_signed='true',
            assertion_consumer_services=[Acs(location='http://test.sp/acs')],
            attribute_consuming_services=[
                Atcs(
                    service_name='test_1',
                    attributes=['spidCode']
                )
            ],
            single_logout_services=[],
            keys=[Key('signing', 'somevalue123')]
        ).to_xml()
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(metadata)
        exc = excinfo.value
        self.assertEqual(
            'EntityDescriptor/SPSSODescriptor/SingleLogoutService',
            exc.details[0].path
        )
        self.assertEqual('required key not provided', exc.details[0].message)

    @patch('testenv.validators._check_certificate', side_effect=fake_check_certificate)
    def test_keydescriptor_no_signing(self, mocked):
        FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        validator = SpidMetadataValidator()
        metadata = create_sp_metadata(
            entity_id='http://test.sp',
            authn_request_signed='true',
            assertion_consumer_services=[Acs(location='http://test.sp/acs')],
            attribute_consuming_services=[
                Atcs(
                    service_name='test_1',
                    attributes=['spidCode']
                )
            ],
            single_logout_services=[
                Slo(binding=BINDING_HTTP_POST, location='http://test.sp/slo')
            ],
            keys=[Key('encryption', 'somevalue123')]
        ).to_xml()
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(metadata)
        exc = excinfo.value
        self.assertEqual(
            'EntityDescriptor/SPSSODescriptor/KeyDescriptor',
            exc.details[0].path
        )
        self.assertEqual('Deve essere presente almeno una chiave con attributo use uguale a "signing"',
                         exc.details[0].message)

    @patch('testenv.validators._check_certificate', side_effect=fake_check_certificate)
    def test_bad_attributes(self, mocked):
        FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        validator = SpidMetadataValidator()
        metadata = create_sp_metadata(
            entity_id='http://test.sp',
            authn_request_signed='true',
            assertion_consumer_services=[Acs(location='http://test.sp/acs')],
            attribute_consuming_services=[
                Atcs(
                    service_name='test_1',
                    attributes=['badAttr']
                )
            ],
            single_logout_services=[
                Slo(binding=BINDING_HTTP_POST, location='http://test.sp/slo')
            ],
            keys=[Key('signing', 'somevalue123')],
            check_attributes=False
        ).to_xml()
        with pytest.raises(SPIDValidationError) as excinfo:
            validator.validate(metadata)
        exc = excinfo.value
        self.assertEqual(
            'EntityDescriptor/SPSSODescriptor/AttributeConsumingService/0/RequestedAttribute/0 - attribute: Name',
            exc.details[0].path
        )
        self.assertEqual('Il valore dell\'elemento non corrisponde a nessuno dei valori attesi ({}):'.format(
            ', '.join(settings.SPID_ATTRIBUTES_NAMES)), exc.details[0].message)

    @patch('testenv.validators._check_certificate', side_effect=fake_check_certificate)
    def test_no_name_format(self, mocked):
        FakeConfig('http://localhost:8088/sso', 'http://localhost:8088/')
        validator = SpidMetadataValidator()
        metadata = create_sp_metadata(
            entity_id='http://test.sp',
            authn_request_signed='true',
            assertion_consumer_services=[Acs(location='http://test.sp/acs')],
            attribute_consuming_services=[
                Atcs(
                    service_name='test_1',
                    attributes=['spidCode']
                )
            ],
            single_logout_services=[
                Slo(binding=BINDING_HTTP_POST, location='http://test.sp/slo')
            ],
            keys=[Key('signing', 'somevalue123')],
            name_format=False
        ).to_xml()
        validator.validate(metadata)
