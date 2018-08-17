# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import load_pem_x509_certificate
from lxml import objectify
from signxml import XMLVerifier

from testenv.exceptions import SignatureVerificationError

SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
SIG_RSA_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'
SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
SIG_RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
SIG_RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
DEPRECATED_ALGORITHMS = {SIG_RSA_SHA1}

SIG_NS = '{http://www.w3.org/2000/09/xmldsig#}'
SIGNATURE = '{}Signature'.format(SIG_NS)
SIGNED_INFO = '{}SignedInfo'.format(SIG_NS)
SIGNATURE_METHOD = '{}SignatureMethod'.format(SIG_NS)
KEY_INFO = '{}KeyInfo'.format(SIG_NS)
X509_DATA = '{}X509Data'.format(SIG_NS)
X509_CERTIFICATE = '{}X509Certificate'.format(SIG_NS)


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


class HTTPPostSignatureVerifier(object):
    def __init__(self, certificate, request, verifier=None):
        self._cert = certificate
        self._request = request
        self._verifier = verifier or XMLVerifier()
        self._xml_doc = objectify.fromstring(request.saml_request)

    @property
    def _supported_algorithms(self):
        return ', '.join(RSA_VERIFIERS.keys())

    def verify(self):
        self._ensure_supported_algorithm()
        self._ensure_matching_certificate()
        self._ensure_matching_digest()
        self._verify()

    def _ensure_supported_algorithm(self):
        sig_alg = self._xml_doc[
            SIGNATURE][SIGNED_INFO][SIGNATURE_METHOD].get('Algorithm')
        if sig_alg in DEPRECATED_ALGORITHMS:
            self._fail(
                "L'algoritmo '{}' è considerato deprecato. Si prega di "
                "utilizzare uno dei seguenti: {}"
                .format(sig_alg, self._supported_algorithms)
            )

    @staticmethod
    def _fail(message):
        raise SignatureVerificationError(message)

    def _ensure_matching_certificate(self):
        request_cert = self._xml_doc[
            SIGNATURE][KEY_INFO][X509_DATA][X509_CERTIFICATE].text
        if normalize_x509(request_cert) != normalize_x509(self._cert):
            self._fail(
                'Il certificato X509 contenuto nella request è differente '
                'rispetto a quello contenuto nei metadata del Service Provider.'
            )

    def _ensure_matching_digest(self):
        # TODO
        pass

    def _verify(self):
        try:
            self._verifier.verify(
                self._request.saml_request, x509_cert=self._cert)
        except InvalidSignature as e:
            print(e)
            self._fail('Verifica della firma fallita.')
