# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import saml2.xmldsig as ds

ALLOWED_SIG_ALGS = [
    ds.SIG_RSA_SHA256,
    ds.SIG_RSA_SHA384,
    ds.SIG_RSA_SHA512,
    ds.SIG_RSA_RIPEMD160,
]

COMPARISONS = ['exact', 'minimum', 'better', 'maximum']

SPID_LEVELS = [
    'https://www.spid.gov.it/SpidL1',
    'https://www.spid.gov.it/SpidL2',
    'https://www.spid.gov.it/SpidL3'
]

AUTH_FAILED_ATTEMPTS = 19
AUTH_WRONG_SPID_LEVEL = 20
AUTH_TIMEOUT = 21
AUTH_NO_CONSENT = 22
AUTH_BLOCKED_CREDENTIALS = 23

STATUS_AUTHN_FAILED = 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed'
SPID_ERRORS = {
    AUTH_FAILED_ATTEMPTS: STATUS_AUTHN_FAILED,
    AUTH_WRONG_SPID_LEVEL: STATUS_AUTHN_FAILED,
    AUTH_TIMEOUT: STATUS_AUTHN_FAILED,
    AUTH_NO_CONSENT: STATUS_AUTHN_FAILED,
    AUTH_BLOCKED_CREDENTIALS: STATUS_AUTHN_FAILED
}

STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'


TIMEDELTA = 2
SIGN_ALG = ds.SIG_RSA_SHA512
DIGEST_ALG = ds.DIGEST_SHA512

SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
DS = 'http://www.w3.org/2000/09/xmldsig#'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
XS = 'http://www.w3.org/2001/XMLSchema'

NSMAP = { 'saml':  SAML, 'samlp': SAMLP, 'ds': DS}
NAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'
NAMEID_FORMAT_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
NAMEID_FORMAT_ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
VERSION = '2.0'
SCM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
