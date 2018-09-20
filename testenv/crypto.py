# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import zlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from lxml import objectify
from lxml.etree import fromstring, tostring
from signxml import XMLSigner, XMLVerifier
from signxml.exceptions import InvalidDigest, InvalidSignature as InvalidSignature_

from testenv.exceptions import SignatureVerificationError
from testenv.settings import (
    DEPRECATED_ALGORITHMS, KEY_INFO, SAML, SIG_NS, SIG_RSA_SHA224, SIG_RSA_SHA256, SIG_RSA_SHA384, SIG_RSA_SHA512,
    SIGNATURE, SIGNATURE_METHOD, SIGNED_INFO, SIGNED_PARAMS, SUPPORTED_ALGORITHMS, X509_CERTIFICATE, X509_DATA,
)

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


def deflate_and_base64_encode(msg):
    if not isinstance(msg, bytes):
        msg = msg.encode('utf-8')
    return base64.b64encode(zlib.compress(msg)[2:-4])


def decode_base64_and_inflate(string):
    return zlib.decompress(base64.b64decode(string), -15)


def pem_format(cert):
    return '\n'.join([
        '-----BEGIN CERTIFICATE-----',
        cert,
        '-----END CERTIFICATE-----',
    ])


def normalize_x509(cert):
    return ''.join(
        cert.replace(
            '-----BEGIN CERTIFICATE-----', ''
        ).replace(
            '-----END CERTIFICATE-----', ''
        ).strip().split()
    )


class RSASigner(object):

    def __init__(self, digest, key=None, padding=None):
        self._key = key
        self._digest = digest
        self._padding = padding or PKCS1v15()

    def sign(self, unsigned_data, key=None):
        if key is None:
            key = self._key
        return key.sign(unsigned_data, self._padding, self._digest)


class RSAVerifier(object):

    def __init__(self, digest, padding=None):
        self._digest = digest
        self._padding = padding or PKCS1v15()

    def verify(self, pubkey, signed_data, signature):
        try:
            pubkey.verify(signature, signed_data, self._padding, self._digest)
        except InvalidSignature:
            return False
        else:
            return True


RSA_VERIFIERS = {
    SIG_RSA_SHA224: RSAVerifier(hashes.SHA224()),
    SIG_RSA_SHA256: RSAVerifier(hashes.SHA256()),
    SIG_RSA_SHA384: RSAVerifier(hashes.SHA384()),
    SIG_RSA_SHA512: RSAVerifier(hashes.SHA512()),
}


RSA_SIGNERS = {
    SIG_RSA_SHA224: RSASigner(hashes.SHA224()),
    SIG_RSA_SHA256: RSASigner(hashes.SHA256()),
    SIG_RSA_SHA384: RSASigner(hashes.SHA384()),
    SIG_RSA_SHA512: RSASigner(hashes.SHA512()),
}


def sign_http_post(xmlstr, key, cert, message=False, assertion=True):
    # We have to use xml-exc-c14n# because when we isolate the Assertion
    # element below, a superfluous xmlns:samlp attribute gets added by etree.tostring()
    # which is not removed by xml-c14n11 (thus generating a wrong digest).
    signer = XMLSigner(
        signature_algorithm='rsa-sha256',
        digest_algorithm='sha256',
        c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#',
    )
    root = fromstring(xmlstr)
    if message:
        root = signer.sign(root, key=key, cert=cert)
    if assertion:
        assertions = root.findall('{%s}Assertion' % SAML)
        for assertion in assertions:
            _assertion = signer.sign(assertion, key=key, cert=cert)
            issuer = _assertion.find('{%s}Issuer' % SAML)
            signature = _assertion.find('%sSignature' % SIG_NS)
            issuer.addnext(signature)
            assertion.getparent().replace(assertion, _assertion)
    response = tostring(root)
    return base64.b64encode(response).decode('ascii')


def sign_http_redirect(xmlstr, key, relay_state=None, req_type='SAMLResponse'):
    encoded_message = deflate_and_base64_encode(xmlstr)
    args = {
        req_type: encoded_message,
        'SigAlg': SIG_RSA_SHA256,
    }
    if relay_state is not None and relay_state.strip() != '':
        args['RelayState'] = relay_state
    query_string = '&'.join(
        [urlencode({k: args[k]})
            for k in SIGNED_PARAMS
            if k in args],
    ).encode('ascii')
    signer = RSA_SIGNERS[SIG_RSA_SHA256]
    key = load_pem_private_key(key, None, default_backend())
    args["Signature"] = base64.b64encode(signer.sign(query_string, key))
    return urlencode(args)


class HTTPRedirectSignatureVerifier(object):

    def __init__(self, certificate, request, verifiers=None):
        self._cert = certificate
        self._request = request
        self._verifiers = verifiers or RSA_VERIFIERS

    @property
    def _supported_algorithms(self):
        return ', '.join(SUPPORTED_ALGORITHMS)

    def verify(self):
        self._ensure_supported_algorithm()
        self._verify_signature()

    def _ensure_supported_algorithm(self):
        self._check_algorithm_deprecation_list()
        self._check_algorithm_whitelist()

    def _check_algorithm_deprecation_list(self):
        if self._request.sig_alg in DEPRECATED_ALGORITHMS:
            self._fail(
                "L'algoritmo '{}' è considerato deprecato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(self._request.sig_alg, self._supported_algorithms)
            )

    @staticmethod
    def _fail(message):
        raise SignatureVerificationError(message)

    def _check_algorithm_whitelist(self):
        if self._request.sig_alg not in SUPPORTED_ALGORITHMS:
            self._fail(
                "L'algoritmo '{}' è sconosciuto o non supportato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(self._request.sig_alg, self._supported_algorithms)
            )

    def _verify_signature(self):
        pubkey = self._get_pubkey()
        verifier = self._verifiers[self._request.sig_alg]
        if not verifier.verify(
                pubkey, self._request.signed_data, self._request.signature):
            self._fail('Verifica della firma fallita.')

    def _get_pubkey(self):
        cert_bytes = pem_format(self._cert).encode('ascii')
        x509 = load_pem_x509_certificate(cert_bytes, backend=default_backend())
        return x509.public_key()


class HTTPPostSignatureVerifier(object):

    def __init__(self, certificate, request, verifier=None):
        self._cert = certificate
        self._request = request
        self._verifier = verifier or XMLVerifier()
        self._xml_doc = objectify.fromstring(request.saml_request.encode('utf-8'))

    @property
    def _supported_algorithms(self):
        return ', '.join(SUPPORTED_ALGORITHMS)

    def verify(self):
        self._ensure_supported_algorithm()
        self._ensure_matching_certificate()
        self._verify_signature()

    def _ensure_supported_algorithm(self):
        self._check_algorithm_deprecation_list()
        self._check_algorithm_whitelist()

    def _check_algorithm_deprecation_list(self):
        sig_alg = self._extract('sig_alg')
        if sig_alg in DEPRECATED_ALGORITHMS:
            self._fail(
                "L'algoritmo '{}' è considerato deprecato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(sig_alg, self._supported_algorithms)
            )

    def _extract(self, key):
        return {
            'sig_alg': (
                self._xml_doc[SIGNATURE][SIGNED_INFO]
                [SIGNATURE_METHOD].get('Algorithm')),
            'certificate': (
                self._xml_doc[SIGNATURE][KEY_INFO][X509_DATA]
                [X509_CERTIFICATE].text),
        }[key]

    @staticmethod
    def _fail(message):
        raise SignatureVerificationError(message)

    def _check_algorithm_whitelist(self):
        sig_alg = self._extract('sig_alg')
        if sig_alg not in SUPPORTED_ALGORITHMS:
            self._fail(
                "L'algoritmo '{}' è sconosciuto o non supportato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(sig_alg, self._supported_algorithms)
            )

    def _ensure_matching_certificate(self):
        request_cert = self._extract('certificate')
        if normalize_x509(request_cert) != normalize_x509(self._cert):
            self._fail(
                'Il certificato X509 contenuto nella request è differente '
                'rispetto a quello contenuto nei metadata del Service Provider.'
            )

    def _verify_signature(self):
        try:
            self._verifier.verify(
                self._request.saml_request, x509_cert=self._cert)
        except InvalidDigest:
            self._fail('Il valore del digest non è valido.')
        except InvalidSignature_:
            self._fail('Verifica della firma fallita.')
