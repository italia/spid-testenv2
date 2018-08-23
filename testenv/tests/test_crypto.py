# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

import pytest

from testenv.crypto import HTTPPostSignatureVerifier, HTTPRedirectSignatureVerifier
from testenv.exceptions import SignatureVerificationError
from testenv.parser import HTTPPostRequest, HTTPRedirectRequest

CERTIFICATE = """\
MIICqDCCAhGgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBxMQswCQYDVQQGEwJpdDEL
MAkGA1UECAwCUk0xEjAQBgNVBAoMCU9wZW5wb2xpczEaMBgGA1UEAwwRc3BpZC5v
cGVucG9saXMuaXQxJTAjBgkqhkiG9w0BCQEWFmd1Z2xpZWxtb0BvcGVucG9saXMu
aXQwHhcNMTcxMDA5MDUzODQ5WhcNMTgxMDA5MDUzODQ5WjBxMQswCQYDVQQGEwJp
dDELMAkGA1UECAwCUk0xEjAQBgNVBAoMCU9wZW5wb2xpczEaMBgGA1UEAwwRc3Bp
ZC5vcGVucG9saXMuaXQxJTAjBgkqhkiG9w0BCQEWFmd1Z2xpZWxtb0BvcGVucG9s
aXMuaXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAONotO3WARQQsB/6Cr8O
Bb+0aR4QsZPCDoenjXUY0kyaj6a2/T8tdznBhIV/j9Fmz++9TueccNTn9PBSz9gO
mentdBSDZalvKUzs4FEuKpj7VUcFdul0n3/dt9co6dBVh6OYyBeiA9id31SlT6IS
NfK10d8C49n1B624GypDxNlFAgMBAAGjUDBOMB0GA1UdDgQWBBRjV9n3eHhabvCD
Q2B/BZII4laxkTAfBgNVHSMEGDAWgBRjV9n3eHhabvCDQ2B/BZII4laxkTAMBgNV
HRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAKf8RoLnJIH5CsqQ5avJnLBtnvTy
fQDVwhestgVdPZoSDM8Vpu5hC/Y+svdNJHT3HYqILePMhS1CmTuuGUz4Ftd5eW/O
gm5+ZP+3dEd6oR3pj1ew/n7kXGf2SzyAPyXkWu67gjn9XYmdtA2tXaEoykkmh4Zn
uNuPpbTpqiRBqCIL"""


SUPPORTED_SIG_ALG = [
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
]


class HTTPRedirectSignatureVerifierTestCase(unittest.TestCase):

    def setUp(self):

        self.cert = CERTIFICATE
        saml_request = '<root></root>'
        relay_state = 'relay_state'
        sig_alg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        signature = (
            b"\xc3y\x17Pb\x9dR@E\x1d\xee\x90\x19\xe6\xf9 Y\x12\x8e\xd9-T\x17UXt\xad \xc5J\xd4`\xea\x85\xe0\xac\xff(/"
            b"\xbc\x9bvO\xae\xa3\xec)\xbf\x8a;\xbb\xe8\xd6R\xe0\xb1\xc3\x04\x18\xc3\xf5\xddK\xb5\xd6{\xbb\xc7\x10"
            b"\x860\xa2z\x03\xe5\xc1\x8d\xdf\xc4\xf7\x95\xdd\x18\xbb\x01\xe0K[\xa5\xfds\x1b\x17\x81\x90\xd8\x14kqd"
            b"\x86\x1eo\xbb#\xc0v\xa6o\x19\xa2\x9b\x13\xd0\xe9\x88'\xfb\x1a\xb2\x1b[\x00\xa8\xf3\xca\xa1\xca"
        )
        signed_data = (
            b'SAMLRequest=synKzy%2Bxs9EHU1wA&RelayState=relay_state&SigAlg=http%3A%2F%2Fwww.w3.org'
            b'%2F2001%2F04%2Fxmldsig-more%23rsa-sha256'
        )

        self.request_data = {
            'saml_request': saml_request,
            'relay_state': relay_state,
            'sig_alg': sig_alg,
            'signature': signature,
            'signed_data': signed_data,
        }
        self.supported_sig_alg = ', '.join(SUPPORTED_SIG_ALG)

    def test_valid_signature(self):
        request = HTTPRedirectRequest(**self.request_data)
        verifier = HTTPRedirectSignatureVerifier(self.cert, request)
        self.assertIsNone(verifier.verify())

    def test_deprecated_algorithm(self):
        self.request_data['sig_alg'] = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
        request = HTTPRedirectRequest(**self.request_data)
        verifier = HTTPRedirectSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual(
            "L'algoritmo 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' è considerato deprecato. "
            "Si prega di utilizzare uno dei seguenti: {}".format(self.supported_sig_alg),
            exc.args[0]
        )

    def test_unknown_algorithm(self):
        self.request_data['sig_alg'] = 'unknown_sig_alg'
        request = HTTPRedirectRequest(**self.request_data)
        verifier = HTTPRedirectSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual(
            "L'algoritmo 'unknown_sig_alg' è sconosciuto o non supportato. Si prega di "
            "utilizzare uno dei seguenti: {}".format(self.supported_sig_alg),
            exc.args[0]
        )

    def test_signature_mismatch(self):
        self.request_data['signed_data'] += b'XXX'
        request = HTTPRedirectRequest(**self.request_data)
        verifier = HTTPRedirectSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual('Verifica della firma fallita.', exc.args[0])


class HTTPPostSignatureVerifierTestCase(unittest.TestCase):

    def setUp(self):
        self.cert = CERTIFICATE
        self.saml_request = """\
<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        AssertionConsumerServiceURL="http://spid-client.local:8000/spid/attributes-consumer/{break_digest}"
        AttributeConsumingServiceIndex="1"
        Destination="spid-testenv.local/sso"
        ID="ONELOGIN_8c420daa204d7bc1a989e072f86a972f96f42c9d"
        IssueInstant="2018-08-21T10:30:01Z"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ProviderName="SP test"
        Version="2.0"
        >
    <saml:Issuer
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        NameQualifier="https://localhost/"
        >https://localhost/</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>{signed_info}</ds:SignedInfo>
        <ds:SignatureValue>{signature_value}</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>{certificate}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"""

        self.signed_info = (
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>'
            '<ds:SignatureMethod Algorithm="{sig_alg}"/>'
            '<ds:Reference URI="#ONELOGIN_8c420daa204d7bc1a989e072f86a972f96f42c9d{break_signature}">'
            '<ds:Transforms>'
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>'
            '</ds:Transforms>'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            '<ds:DigestValue>QyvCIXFML2A9pbw3bgDQxdZ152OmlZxSebZwrmgCZro=</ds:DigestValue>'
            '</ds:Reference>'
        )

        self.signature_value = (
            'IR6aLXJdKQ29IdgMlR9+nhANkhTZQ14x0Z2pvHb/FDWd9gmRuaMZgW6Jgrbg22U0MLxr+jlOcodFjV+iJSoV5H0IFlHWEyrNYpqU4CgB+'
            'ilxNtY+7jDnxA2OOXaUleqN7iTTb/EmGIOk29BCi0DeRP9mYLKZ9vWKzZ9Ie87I1pI='
        )

        self.sig_alg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        self.supported_sig_alg = ', '.join(SUPPORTED_SIG_ALG)

    def test_valid_signature(self):
        saml_request = self.saml_request.format(
            break_digest='',
            signature_value=self.signature_value,
            signed_info=self.signed_info.format(sig_alg=self.sig_alg, break_signature=''),
            certificate=self.cert,
        )
        relay_state = 'relay_state'
        request = HTTPPostRequest(saml_request=saml_request, relay_state=relay_state)
        verifier = HTTPPostSignatureVerifier(self.cert, request)
        self.assertIsNone(verifier.verify())

    def test_deprecated_algorithm(self):
        sig_alg = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
        saml_request = self.saml_request.format(
            break_digest='',
            signature_value=self.signature_value,
            signed_info=self.signed_info.format(sig_alg=sig_alg, break_signature=''),
            certificate=self.cert,
        )
        relay_state = 'relay_state'
        request = HTTPPostRequest(saml_request=saml_request, relay_state=relay_state)
        verifier = HTTPPostSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual(
            "L'algoritmo 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' è considerato deprecato. "
            "Si prega di utilizzare uno dei seguenti: {}".format(self.supported_sig_alg),
            exc.args[0]
        )

    def test_unknown_algorithm(self):
        sig_alg = 'unknown_sig_alg'
        saml_request = self.saml_request.format(
            break_digest='',
            signature_value=self.signature_value,
            signed_info=self.signed_info.format(sig_alg=sig_alg, break_signature=''),
            certificate=self.cert,
        )
        relay_state = 'relay_state'
        request = HTTPPostRequest(saml_request=saml_request, relay_state=relay_state)
        verifier = HTTPPostSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual(
            "L'algoritmo 'unknown_sig_alg' è sconosciuto o non supportato. Si prega di "
            "utilizzare uno dei seguenti: {}".format(self.supported_sig_alg),
            exc.args[0]
        )

    def test_certificate_mismatch(self):
        saml_request = self.saml_request.format(
            break_digest='',
            signature_value=self.signature_value,
            signed_info=self.signed_info.format(sig_alg=self.sig_alg, break_signature=''),
            certificate='fake cert',
        )
        relay_state = 'relay_state'
        request = HTTPPostRequest(saml_request=saml_request, relay_state=relay_state)
        verifier = HTTPPostSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual(
            'Il certificato X509 contenuto nella request è differente '
            'rispetto a quello contenuto nei metadata del Service Provider.',
            exc.args[0]
        )

    def test_digest_mismatch(self):
        saml_request = self.saml_request.format(
            break_digest='broken',
            signature_value=self.signature_value,
            signed_info=self.signed_info.format(sig_alg=self.sig_alg, break_signature=''),
            certificate=self.cert,
        )
        relay_state = 'relay_state'
        request = HTTPPostRequest(saml_request=saml_request, relay_state=relay_state)
        verifier = HTTPPostSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual('Il valore del digest non è valido.', exc.args[0])

    def test_signature_mismatch(self):
        saml_request = self.saml_request.format(
            break_digest='',
            signature_value=self.signature_value,
            signed_info=self.signed_info.format(sig_alg=self.sig_alg, break_signature='broken'),
            certificate=self.cert,
        )
        relay_state = 'relay_state'
        request = HTTPPostRequest(saml_request=saml_request, relay_state=relay_state)
        verifier = HTTPPostSignatureVerifier(self.cert, request)
        with pytest.raises(SignatureVerificationError) as excinfo:
            verifier.verify()
        exc = excinfo.value
        self.assertEqual('Verifica della firma fallita.', exc.args[0])
