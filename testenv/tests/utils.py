# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from lxml import etree

try:
    # Replace this try-except with
    # from six.moves import StringIO
    from StringIO import StringIO
except ImportError:
    from io import StringIO


def validate_xml(xml_string, xsd_path):
    with open(xsd_path) as fh:
        xmlschema_doc = etree.parse(fh)
    xmlschema = etree.XMLSchema(xmlschema_doc)
    # Decode bytes object and preserve strings and unicode(py2).
    if isinstance(xml_string, bytes):
        xml_string = xml_string.decode("utf-8")
    return xmlschema.validate(etree.parse(StringIO(xml_string)))


class FakeRequest(object):

    def __init__(self, data):
        self.saml_request = data
