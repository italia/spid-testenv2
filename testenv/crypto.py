# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import load_pem_x509_certificate

from testenv.exceptions import SignatureVerificationError

SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
SIG_RSA_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'
SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
SIG_RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
SIG_RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
DEPRECATED_ALGORITHMS = {SIG_RSA_SHA1}


def pem_format(cert):
    return '\n'.join([
        '-----BEGIN CERTIFICATE-----',
        cert,
        '-----END CERTIFICATE-----',
    ])


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


class HTTPRedirectSignatureVerifier(object):
    def __init__(self, certificate, request, verifiers=None):
        self._cert = certificate
        self._request = request
        self._verifiers = verifiers or RSA_VERIFIERS

    @property
    def _supported_algorithms(self):
        return ', '.join(self._verifiers.keys())

    def verify(self):
        self._ensure_supported_algorithm()
        pubkey = self._get_pubkey()
        verifier = self._select_verifier()
        if not verifier.verify(
                pubkey, self._request.signed_data, self._request.signature):
            self._fail('Verifica della firma fallita.')

    def _ensure_supported_algorithm(self):
        if self._request.sig_alg in DEPRECATED_ALGORITHMS:
            self._fail(
                "L'algoritmo '{}' è considerato deprecato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(self._request.sig_alg, self._supported_algorithms)
            )

    def _get_pubkey(self):
        cert_bytes = pem_format(self._cert).encode('ascii')
        x509 = load_pem_x509_certificate(cert_bytes, backend=default_backend())
        return x509.public_key()

    @staticmethod
    def _fail(message):
        raise SignatureVerificationError(message)

    def _select_verifier(self):
        try:
            return self._verifiers[self._request.sig_alg]
        except KeyError:
            self._fail(
                "L'algoritmo '{}' è sconosciuto o non supportato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(self._request.sig_alg, self._supported_algorithms)
            )
