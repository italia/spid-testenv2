# -*- coding: utf-8 -*-
from __future__ import unicode_literals

# SPID

SPID_LEVEL_1 = 'https://www.spid.gov.it/SpidL1'
SPID_LEVEL_2 = 'https://www.spid.gov.it/SpidL2'
SPID_LEVEL_3 = 'https://www.spid.gov.it/SpidL3'


SPID_LEVELS = [
    SPID_LEVEL_1,
    SPID_LEVEL_2,
    SPID_LEVEL_3
]

SPID_ATTRIBUTES = {
    'primary': {
        'spidCode': 'string',
        'name': 'string',
        'familyName': 'string',
        'placeOfBirth': 'string',
        'countryOfBirth': 'string',
        'dateOfBirth': 'date',
        'gender': 'string',
        'companyName': 'string',
        'registeredOffice': 'string',
        'fiscalNumber': 'string',
        'ivaCode': 'string',
        'idCard': 'string',
    },
    'secondary': {
        'mobilePhone': 'string',
        'email': 'string',
        'address': 'string',
        'expirationDate': 'date',
        'digitalAddress': 'string'
    }
}


#######

# SAML2
COMPARISONS = ['exact', 'minimum', 'better', 'maximum']
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


SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
DS = 'http://www.w3.org/2000/09/xmldsig#'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
XS = 'http://www.w3.org/2001/XMLSchema'
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'

NSMAP = { 'saml':  SAML, 'samlp': SAMLP, 'ds': DS, 'md': MD}
NAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'
NAMEID_FORMAT_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
NAMEID_FORMAT_ENTITY = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
VERSION = '2.0'
SCM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


BINDING_HTTP_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
BINDING_HTTP_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'

################

# Parsing errors

MANDATORY_ERROR = 'L\'attributo è obbligatorio'
NO_WANT_ERROR = 'L\'attributo non è richiesto'
DEFAULT_VALUE_ERROR = 'è diverso dal valore di riferimento {}'
DEFAULT_LIST_VALUE_ERROR = 'non corrisponde a nessuno '\
                           'dei valori contenuti in {}'


# Crypto

SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
SIG_RSA_SHA224 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224'
SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
SIG_RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
SIG_RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
DEPRECATED_ALGORITHMS = [SIG_RSA_SHA1]
SUPPORTED_ALGORITHMS = [SIG_RSA_SHA224, SIG_RSA_SHA256, SIG_RSA_SHA384, SIG_RSA_SHA512]

SIG_NS = '{http://www.w3.org/2000/09/xmldsig#}'

SIGNATURE = '{}Signature'.format(SIG_NS)
SIGNED_INFO = '{}SignedInfo'.format(SIG_NS)
SIGNATURE_METHOD = '{}SignatureMethod'.format(SIG_NS)
KEY_INFO = '{}KeyInfo'.format(SIG_NS)
X509_DATA = '{}X509Data'.format(SIG_NS)
X509_CERTIFICATE = '{}X509Certificate'.format(SIG_NS)

SIGNED_PARAMS = ['SAMLRequest', 'RelayState', 'SigAlg']

########


# Misc
TIMEDELTA = 2 # minutes (used to verify and generate range limits for issue instant etc.)
CHALLENGES_TIMEOUT = 30 # seconds (used to verify spid level >= 2 challenges)

MULTIPLE_OCCURRENCES_TAGS = {}
