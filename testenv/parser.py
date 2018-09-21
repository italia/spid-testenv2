# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import re
import zlib
from base64 import b64decode
from collections import namedtuple

from lxml import etree, objectify

from testenv.exceptions import DeserializationError, RequestParserError, ValidationError
from testenv.settings import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, MULTIPLE_OCCURRENCES_TAGS
from testenv.validators import AuthnRequestXMLSchemaValidator, SpidValidator, ValidatorGroup, XMLFormatValidator

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


SIGNED_PARAMS = ['SAMLRequest', 'RelayState', 'SigAlg']


HTTPRedirectRequest = namedtuple(
    'HTTPRedirectRequest',
    ['saml_request', 'relay_state', 'sig_alg', 'signature', 'signed_data', 'auto_login'],
)


HTTPPostRequest = namedtuple(
    'HTTPPostRequest', ['saml_request', 'relay_state'])


def _get_deserializer(request, action, binding):
    validators = [
        XMLFormatValidator(),
        AuthnRequestXMLSchemaValidator(),
        SpidValidator(action, binding),
    ]
    validator_group = ValidatorGroup(validators)
    return HTTPRequestDeserializer(request, validator_group)


def get_http_redirect_request_deserializer(request, action):
    return _get_deserializer(request, action, BINDING_HTTP_REDIRECT)


def get_http_post_request_deserializer(request, action):
    return _get_deserializer(request, action, BINDING_HTTP_POST)


class HTTPRedirectRequestParser(object):

    def __init__(self, querystring, request_class=None):
        self._querystring = querystring
        self._request_class = request_class or HTTPRedirectRequest
        self._saml_request = None
        self._relay_state = None
        self._sig_alg = None
        self._signature = None
        self._signed_data = None
        self._auto_login = None

    def parse(self):
        self._saml_request = self._parse_saml_request()
        self._relay_state = self._parse_relay_state()
        self._sig_alg = self._parse_sig_alg()
        self._signature = self._parse_signature()
        self._signed_data = self._build_signed_data()
        self._auto_login = self._build_auto_login()
        return self._build_request()

    def _parse_saml_request(self):
        saml_request = self._extract('SAMLRequest')
        return self._decode_saml_request(saml_request)

    def _extract(self, key):
        try:
            return self._querystring[key]
        except KeyError as e:
            self._fail("Dato mancante nella request: '{}'".format(e.args[0]))

    @staticmethod
    def _fail(message):
        raise RequestParserError(message)

    def _decode_saml_request(self, saml_request):
        try:
            return self._convert_saml_request(saml_request)
        except Exception:  # FIXME detail exceptions
            self._fail("Impossibile decodificare l'elemento 'SAMLRequest'")

    @staticmethod
    def _convert_saml_request(saml_request):
        saml_request = b64decode(saml_request)
        saml_request = zlib.decompress(saml_request, -15)
        return saml_request

    def _parse_relay_state(self):
        try:
            return self._extract('RelayState')
        except RequestParserError:
            return None

    def _parse_sig_alg(self):
        return self._extract('SigAlg')

    def _parse_signature(self):
        signature = self._extract('Signature')
        return self._decode_signature(signature)

    def _decode_signature(self, signature):
        try:
            return b64decode(signature)
        except Exception:
            self._fail("Impossibile decodificare l'elemento 'Signature'")

    def _build_signed_data(self):
        signed_data = '&'.join(
            [urlencode({k: self._querystring[k]})
             for k in SIGNED_PARAMS
             if k in self._querystring],
        )
        return signed_data.encode('ascii')

    def _build_auto_login(self):
        auto_login = self._querystring.get('auto_login', None)
        return auto_login

    def _build_request(self):
        return self._request_class(
            self._saml_request,
            self._relay_state,
            self._sig_alg,
            self._signature,
            self._signed_data,
            self._auto_login
        )


class HTTPPostRequestParser(object):

    def __init__(self, form, request_class=None):
        self._form = form
        self._request_class = request_class or HTTPPostRequest
        self._saml_request = None
        self._relay_state = None

    def parse(self):
        self._saml_request = self._parse_saml_request()
        self._relay_state = self._parse_relay_state()
        return self._build_request()

    def _parse_saml_request(self):
        saml_request = self._extract('SAMLRequest')
        return self._decode_saml_request(saml_request)

    def _extract(self, key):
        try:
            return self._form[key]
        except KeyError as e:
            self._fail("Dato mancante nella request: '{}'".format(e.args[0]))

    @staticmethod
    def _fail(message):
        raise RequestParserError(message)

    def _decode_saml_request(self, saml_request):
        try:
            return self._convert_saml_request(saml_request)
        except Exception:  # FIXME detail exceptions
            self._fail("Impossibile decodificare l'elemento 'SAMLRequest'")

    @staticmethod
    def _convert_saml_request(saml_request):
        saml_request = b64decode(saml_request)
        return saml_request

    def _parse_relay_state(self):
        try:
            return self._extract('RelayState')
        except RequestParserError:
            return None

    def _build_request(self):
        return self._request_class(self._saml_request, self._relay_state)


class HTTPRequestDeserializer(object):

    def __init__(self, request, validator, saml_class=None):
        self._request = request
        self._validator = validator
        self._saml_class = saml_class or SAMLTree

    def deserialize(self):
        self._validate()
        return self._deserialize()

    def _validate(self):
        try:
            self._validator.validate(self._request)
        except ValidationError as e:
            raise DeserializationError(
                self._request.saml_request,
                e.details,
            )

    def _deserialize(self):
        xml_doc = objectify.fromstring(self._request.saml_request)
        return self._saml_class(xml_doc)


class SAMLTree(object):

    def __init__(self, xml_doc, multi_occur_tags=None):
        self._xml_doc = xml_doc
        self._multi_occur_tags = multi_occur_tags or MULTIPLE_OCCURRENCES_TAGS
        self.text = self._xml_doc.text
        self._bind_tag()
        self._bind_attributes()
        self._bind_subtrees()

    def _bind_tag(self):
        tag = etree.QName(self._xml_doc).localname
        self.tag = self._to_snake_case(tag)

    @staticmethod
    def _to_snake_case(child_name):
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', child_name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

    def _bind_attributes(self):
        for attr_name, attr_val in self._xml_doc.attrib.items():
            attr_name = self._to_snake_case(attr_name)
            setattr(self, attr_name, attr_val)

    def _bind_subtrees(self):
        for child in self._xml_doc.iterchildren():
            child_name = self._to_snake_case(etree.QName(child).localname)
            subtree = SAMLTree(child, self._multi_occur_tags)
            if child.tag in self._multi_occur_tags:
                self._handle_as_list(child_name, subtree)
            else:
                setattr(self, child_name, subtree)

    def _handle_as_list(self, child_name, subtree):
        existing = getattr(self, child_name, None)
        if isinstance(existing, list):
            existing.append(subtree)
        else:
            setattr(self, child_name, [subtree])
