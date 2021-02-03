import base64
import unittest
import zlib
from copy import copy
from urllib.parse import urlencode

import pytest
from lxml import objectify

from testenv.exceptions import (
    DeserializationError, RequestParserError, SPIDValidationError, XMLFormatValidationError, XMLSchemaValidationError,
)
from testenv.parser import HTTPPostRequestParser, HTTPRedirectRequestParser, HTTPRequestDeserializer, SAMLTree
from testenv.tests.utils import FakeRequest
from testenv.utils import saml_to_dict
from testenv.validators import ValidatorGroup


class FakeSAMLClass:

    def __init__(self, data):
        self.data = data


class SuccessValidator:

    @staticmethod
    def validate(request):
        return None


class FailValidator:

    def __init__(self, exc):
        self._exc = exc

    def validate(self, request):
        raise self._exc


class HTTPRedirectRequestParserTestCase(unittest.TestCase):

    def setUp(self):
        compressor = zlib.compressobj(-1, zlib.DEFLATED, -15)
        compressor.compress(b'saml_request')
        compressed = compressor.flush()
        saml_request = base64.b64encode(compressed).decode('ascii')
        relay_state = 'relay_state'
        sig_alg = 'sig_alg'
        signature = base64.b64encode(b'signature').decode('ascii')
        self.querystring = {
            'SAMLRequest': saml_request,
            'RelayState': relay_state,
            'SigAlg': sig_alg,
            'Signature': signature,
        }

    def test_valid_request(self):
        parser = HTTPRedirectRequestParser(self.querystring)
        parsed = parser.parse()
        self.assertEqual(parsed.saml_request, b'saml_request')
        self.assertEqual(parsed.sig_alg, 'sig_alg')
        self.assertEqual(parsed.relay_state, 'relay_state')
        self.assertEqual(parsed.signature, b'signature')
        signed_data = urlencode([
            ('SAMLRequest', self.querystring['SAMLRequest']),
            ('RelayState', self.querystring['RelayState']),
            ('SigAlg', self.querystring['SigAlg']),
        ]).encode('ascii')
        self.assertEqual(parsed.signed_data, signed_data)

    def test_relay_state_is_optional(self):
        del self.querystring['RelayState']
        parser = HTTPRedirectRequestParser(self.querystring)
        parsed = parser.parse()
        self.assertIsNone(parsed.relay_state)

    def test_missing_data(self):
        for key in ['SAMLRequest', 'SigAlg', 'Signature']:
            qs = copy(self.querystring)
            del qs[key]
            parser = HTTPRedirectRequestParser(qs)
            with pytest.raises(RequestParserError) as excinfo:
                parser.parse()
            exc = excinfo.value
            self.assertEqual(
                "Dato mancante nella request: '{}'".format(key),
                exc.args[0])

    def test_decoding_failure(self):
        for key in ['SAMLRequest', 'Signature']:
            qs = copy(self.querystring)
            qs[key] = 'XXX_not_base64_data_XXX'
            parser = HTTPRedirectRequestParser(qs)
            with pytest.raises(RequestParserError) as excinfo:
                parser.parse()
            exc = excinfo.value
            self.assertEqual(
                "Impossibile decodificare l'elemento '{}'".format(key),
                exc.args[0])


class HTTPPostRequestParserTestCase(unittest.TestCase):

    def setUp(self):
        saml_request = base64.b64encode(b'saml_request').decode('ascii')
        relay_state = 'relay_state'
        self.form = {
            'SAMLRequest': saml_request,
            'RelayState': relay_state,
        }

    def test_valid_request(self):
        parser = HTTPPostRequestParser(self.form)
        parsed = parser.parse()
        self.assertEqual(parsed.saml_request, b'saml_request')
        self.assertEqual(parsed.relay_state, 'relay_state')

    def test_relay_state_is_optional(self):
        del self.form['RelayState']
        parser = HTTPPostRequestParser(self.form)
        parsed = parser.parse()
        self.assertIsNone(parsed.relay_state)

    def test_missing_data(self):
        del self.form['SAMLRequest']
        parser = HTTPPostRequestParser(self.form)
        with pytest.raises(RequestParserError) as excinfo:
            parser.parse()
        exc = excinfo.value
        self.assertEqual(
            "Dato mancante nella request: 'SAMLRequest'",
            exc.args[0])

    def test_decoding_failure(self):
        self.form['SAMLRequest'] = 'XXX_not_base64_data_XXX'
        parser = HTTPPostRequestParser(self.form)
        with pytest.raises(RequestParserError) as excinfo:
            parser.parse()
        exc = excinfo.value
        self.assertEqual(
            "Impossibile decodificare l'elemento 'SAMLRequest'",
            exc.args[0])


class HTTPRequestDeserializerTestCase(unittest.TestCase):

    def test_successful_deserialization(self):
        validator = ValidatorGroup([SuccessValidator(), SuccessValidator()])
        request = FakeRequest('<xml></xml>')
        deserializer = HTTPRequestDeserializer(
            request, validator=validator, saml_class=FakeSAMLClass)
        deserialized = deserializer.deserialize()
        self.assertIsInstance(deserialized, FakeSAMLClass)

    def test_blocking_validation_failure(self):
        xml = '<xml></xml>'
        blocking_validator = FailValidator(
            XMLFormatValidationError(['blocking error']))
        nonblocking_validator = FailValidator(
            XMLSchemaValidationError(['nonblocking error']))
        validator = ValidatorGroup([blocking_validator, nonblocking_validator])
        request = FakeRequest(xml)
        deserializer = HTTPRequestDeserializer(
            request, validator=validator, saml_class=FakeSAMLClass)
        with pytest.raises(DeserializationError) as excinfo:
            deserializer.deserialize()
        exc = excinfo.value
        self.assertEqual(len(exc.details), 1)
        self.assertEqual(exc.details[0], 'blocking error')
        self.assertEqual(exc.initial_data, xml)

    def test_nonblocking_validation_failure(self):
        xml = '<xml></xml>'
        first_nonblocking_validator = FailValidator(
            XMLSchemaValidationError(['a nonblocking error']))
        second_nonblocking_validator = FailValidator(
            SPIDValidationError(['another nonblocking error']))
        validator = ValidatorGroup([
            first_nonblocking_validator,
            second_nonblocking_validator,
        ])
        request = FakeRequest(xml)
        deserializer = HTTPRequestDeserializer(
            request, validator=validator, saml_class=FakeSAMLClass)
        with pytest.raises(DeserializationError) as excinfo:
            deserializer.deserialize()
        exc = excinfo.value
        self.assertEqual(len(exc.details), 2)
        self.assertEqual(exc.details[0], 'a nonblocking error')
        self.assertEqual(exc.details[1], 'another nonblocking error')
        self.assertEqual(exc.initial_data, xml)


class SAMLTreeTestCase(unittest.TestCase):

    def test_deserialization(self):
        xml = """\
<root>
    <child1>some data</child1>
    <child2 AnAttribute="more data"></child2>
    <SpecialChild3>
        <Item AnotherAttribute="foo"></Item>
        <Item EvenAnotherAttribute="bar"></Item>
    </SpecialChild3>
</root>"""
        xml_doc = objectify.fromstring(xml)
        saml_tree = SAMLTree(xml_doc, multi_occur_tags={'Item'})
        self.assertEqual(saml_tree.child1.text, 'some data')
        self.assertEqual(saml_tree.child1.tag, 'child1')
        self.assertEqual(saml_tree.child2.an_attribute, 'more data')
        self.assertEqual(len(saml_tree.special_child3.item), 2)
        self.assertEqual(saml_tree.special_child3.tag, 'special_child3')
        self.assertEqual(saml_tree.special_child3.item[
                         0].another_attribute, 'foo')
        self.assertEqual(saml_tree.special_child3.item[
                         1].even_another_attribute, 'bar')


class SAMLStupidMetadataTestCase(unittest.TestCase):
    def test_broken_metadata_xml_valuerror(self):
        with open("testenv/tests/data/sp-invalid-xml-starttag.xml") as xmlstr:
            self.assertEqual({}, saml_to_dict(xmlstr))

    def test_stupid_metadata_xml_valuerror(self):
        saml_to_dict('test.stupido')
