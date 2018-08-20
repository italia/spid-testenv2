# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
from copy import copy
import unittest
import zlib

import pytest

from testenv.exceptions import RequestParserError
from testenv.parser import HTTPRedirectRequestParser

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


class HTTPRedirectRequestParserTestCase(unittest.TestCase):

    def setUp(self):
        compressor = zlib.compressobj(wbits=-15)
        compressor.compress(b'saml_request')
        compressed = compressor.flush()
        saml_request = base64.b64encode(compressed).decode('ascii')
        sig_alg = 'sig_alg'
        signature = base64.b64encode(b'signature').decode('ascii')
        self.querystring = {
            'SAMLRequest': saml_request,
            'SigAlg': sig_alg,
            'Signature': signature,
        }

    def test_valid_request(self):
        parser = HTTPRedirectRequestParser(self.querystring)
        parsed = parser.parse()
        self.assertEqual(parsed.saml_request, 'saml_request')
        self.assertEqual(parsed.sig_alg, 'sig_alg')
        self.assertEqual(parsed.signature, b'signature')
        signed_data = urlencode([
            ('SAMLRequest', self.querystring['SAMLRequest']),
            ('SigAlg', self.querystring['SigAlg']),
        ]).encode('ascii')
        self.assertEqual(parsed.signed_data, signed_data)

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
