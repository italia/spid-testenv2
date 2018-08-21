# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import sys
from importlib import import_module

from saml2.attribute_converter import AttributeConverter
from saml2.s_utils import do_ava, factory
from saml2.saml import Attribute


def ac_factory(path="", **kwargs):
    """Attribute Converter factory

    :param path: The path to a directory where the attribute maps are expected
        to reside.
    :return: A AttributeConverter instance

    See: https://github.com/IdentityPython/pysaml2/blob/master/src/saml2/attribute_converter.py#L52
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
        # See: https://github.com/IdentityPython/pysaml2/blob/master/src/saml2/attribute_converter.py#L274
        super(SpidAttributeConverter, self).__init__(name_format)
        self._special_cases = special_cases

    def to_(self, attrvals):
        """ Create a list of Attribute instances.

        :param attrvals: A dictionary of attributes and values
        :return: A list of Attribute instances

        See: https://github.com/IdentityPython/pysaml2/blob/master/src/saml2/attribute_converter.py#L486
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
