# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import collections
import os
import sys
from importlib import import_module

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.assertion import Policy
from saml2.attribute_converter import AttributeConverter
from saml2.entity import UnknownBinding
from saml2.request import AuthnRequest, LogoutRequest
from saml2.response import IncorrectlySigned
from saml2.s_utils import (UnravelError, decode_base64_and_inflate, do_ava,
                           factory)
from saml2.saml import Attribute
from saml2.server import Server
from testenv.exceptions import SpidValidationError


class Observer(object):

    def __init__(self, *args, **kwargs):
        self._pool = collections.OrderedDict()

    def attach(self, obj):
        self._pool[obj._name] = obj
        for _child in obj._children:
            self.attach(_child)

    def evaluate(self):
        _errors = []
        for elem, obj in self._pool.items():
            if obj._errors:
                _errors.append([elem, obj._tag, obj._errors])
        return _errors


class RequestMixin(object):
    def _loads(self, xmldata, binding=None, origdoc=None, must=None,
            only_valid_cert=False):
        if binding == BINDING_HTTP_REDIRECT:
            pass

        # own copy
        self.xmlstr = xmldata[:]
        #logger.debug("xmlstr: %s", self.xmlstr)
        try:
            print(self.signature_check)
            self.message = self.signature_check(xmldata, origdoc=origdoc,
                                                must=must,
                                                only_valid_cert=only_valid_cert)
        except TypeError as e:
            raise
        except Exception as excp:
            pass
            # logger.info("EXCEPTION: %s", excp)

        if not self.message:
            # logger.error("Response was not correctly signed")
            # logger.info("Response: %s", xmldata)
            raise IncorrectlySigned()

        #logger.info("request: %s", self.message)
        from testenv.parser import XMLValidator
        errors = XMLValidator().validate_authnrequest(self.xmlstr)
        if errors:
            raise SpidValidationError(xml=self.xmlstr, validation_errors=errors)
        return self


class SpidAuthnRequest(RequestMixin, AuthnRequest):
    def verify(self):
        # TODO: move here a bit of parsing flow
        return self


class SpidLogoutRequest(RequestMixin, LogoutRequest):
    def verify(self):
        # TODO: move here a bit of parsing flow
        return self


class SpidServer(Server):
    def parse_authn_request(self, enc_request, binding=BINDING_HTTP_REDIRECT):
        """Parse a Authentication Request

        :param enc_request: The request in its transport format
        :param binding: Which binding that was used to transport the message
            to this entity.
        :return: A request instance
        """

        return self._parse_request(enc_request, SpidAuthnRequest,
                                   "single_sign_on_service", binding)

    def parse_logout_request(self, xmlstr, binding=BINDING_HTTP_REDIRECT):
        """ Deal with a LogoutRequest

        :param xmlstr: The response as a xml string
        :param binding: What type of binding this message came through.
        :return: None if the reply doesn't contain a valid SAML LogoutResponse,
            otherwise the reponse if the logout was successful and None if it
            was not.
        """

        return self._parse_request(xmlstr, SpidLogoutRequest,
                                   "single_logout_service", binding)

    @staticmethod
    def unravel(txt, binding, msgtype="response"):
        """
        Will unpack the received text. Depending on the context the original
            response may have been transformed before transmission.
        :param txt:
        :param binding:
        :param msgtype:
        :return:
        """
        if binding not in [
            BINDING_HTTP_REDIRECT, BINDING_HTTP_POST, None
        ]:
            raise UnknownBinding("Don't know how to handle '%s'" % binding)
        else:
            try:
                if binding == BINDING_HTTP_REDIRECT:
                    xmlstr = decode_base64_and_inflate(txt)
                elif binding == BINDING_HTTP_POST:
                    xmlstr = base64.b64decode(txt)
                else:
                    xmlstr = txt
            except Exception:
                raise UnravelError("Unravelling binding '%s' failed" % binding)
        return xmlstr


class SpidPolicy(Policy):

    def __init__(self, restrictions=None, index=None):
        super(SpidPolicy, self).__init__(restrictions=restrictions)
        self.index = index

    def restrict(self, ava, sp_entity_id, metadata=None):
        """ Identity attribute names are expected to be expressed in
        the local lingo (== friendlyName)

        :return: A filtered ava according to the IdPs/AAs rules and
            the list of required/optional attributes according to the SP.
            If the requirements can't be met an exception is raised.
        """
        if metadata:
            spec = metadata.attribute_requirement(
                sp_entity_id, index=self.index
            )
            if spec:
                return self.filter(ava, sp_entity_id, metadata,
                                   spec["required"], spec["optional"])

        return self.filter(ava, sp_entity_id, metadata, [], [])


def ac_factory(path="", **kwargs):
    """Attribute Converter factory

    :param path: The path to a directory where the attribute maps are expected
        to reside.
    :return: A AttributeConverter instance
    """
    acs = []

    if path:
        if path not in sys.path:
            sys.path.insert(0, path)

        for fil in os.listdir(path):
            if fil.endswith(".py"):
                mod = import_module(fil[:-3])
                for key, item in mod.__dict__.items():
                    if key.startswith("__"):
                        continue
                    if isinstance(item,
                                  dict) and "to" in item and "fro" in item:
                        atco = SpidAttributeConverter(
                            item["identifier"],
                            kwargs.get('override_types', {})
                        )
                        atco.from_dict(item)
                        acs.append(atco)
    else:
        from saml2 import attributemaps

        for typ in attributemaps.__all__:
            mod = import_module(".%s" % typ, "saml2.attributemaps")
            for key, item in mod.__dict__.items():
                if key.startswith("__"):
                    continue
                if isinstance(item, dict) and "to" in item and "fro" in item:
                    atco = SpidAttributeConverter(
                        item["identifier"],
                        kwargs.get('override_types', {})
                    )
                    atco.from_dict(item)
                    acs.append(atco)

    return acs


class SpidAttributeConverter(AttributeConverter):

    def __init__(self, name_format="", special_cases={}):
        super(SpidAttributeConverter, self).__init__(name_format)
        self._special_cases = special_cases

    def to_(self, attrvals):
        """ Create a list of Attribute instances.

        :param attrvals: A dictionary of attributes and values
        :return: A list of Attribute instances
        """
        attributes = []
        for key, value in attrvals.items():
            name = self._to.get(key.lower())
            if name:
                typ = self._special_cases.get(name, '')
                attr_value = do_ava(value, typ)
                attributes.append(factory(Attribute,
                                          name=name,
                                          name_format=self.name_format,
                                          attribute_value=attr_value))
            else:
                attributes.append(factory(Attribute,
                                          name=key,
                                          attribute_value=do_ava(value)))

        return attributes
