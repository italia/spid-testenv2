# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from datetime import datetime
from hashlib import sha1
from uuid import uuid4

from lxml.builder import ElementMaker
from lxml.etree import Element, SubElement, tostring

SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
DS = 'http://www.w3.org/2000/09/xmldsig#'

NSMAP = { 'saml':  SAML, 'samlp': SAMLP, 'ds': DS }


samlp_maker = ElementMaker(
    namespace=SAMLP,
    nsmap=dict(samlp=SAMLP),
)
saml_maker = ElementMaker(
    namespace=SAML,
    nsmap=dict(saml=SAML),
)

ds_maker = ElementMaker(
    namespace=DS,
    nsmap=dict(saml=DS),
)

MAKERS = {
    'saml': saml_maker,
    'samlp': samlp_maker,
    'ds': ds_maker
}

class SamlMixin(object):
    saml_type = None
    defaults = {}

    def __init__(self, attrib={}, text=None, *args, **kwargs):
        tag = '{%s}' % NSMAP[self.saml_type] + self.class_name
        E = MAKERS.get(self.saml_type)
        attributes = self.defaults.copy()
        attributes.update(attrib.copy())
        self._element = getattr(E, tag)(
            **attributes,
        )
        if text is not None:
            self._element.text = text

    @property
    def class_name(self):
        return self.__class__.__name__

    def to_xml(self):
        return tostring(self.tree)

    @property
    def tree(self):
        return self._element

    def append(self, el):
        self.tree.append(el.tree)

class LogoutResponse(SamlMixin):
    saml_type = 'saml'
    defaults = {
        'Version': '2.0'
    }


class Issuer(SamlMixin):
    saml_type = 'saml'
    defaults = {
        'Format': 'urn:oasis:names:tc:SAML:2.0:nameidformat:entity'
    }

class Status(SamlMixin):
    saml_type = 'samlp'


class StatusCode(SamlMixin):
    saml_type = 'samlp'


class StatusDetail(SamlMixin):
    saml_type = 'samlp'


class StatusMessage(SamlMixin):
    saml_type = 'samlp'


class Signature(SamlMixin):
    saml_type = 'ds'


def generate_unique_id():
    """
    Generates an unique string (used for example as ID for assertions).
    :return: A unique string
    :rtype: string
    """
    return 'id_{}'.format(sha1(uuid4().hex.encode('utf-8')).hexdigest())


def create_logout_response(data, response_status):
    issue_instant = datetime.utcnow()
    issue_instant = issue_instant.replace(microsecond=0)
    issue_instant = issue_instant.isoformat() + 'Z'
    logout_response_attrs = data.get('logout_response').get('attrs')
    response = LogoutResponse(
        attrib = dict(
            ID=generate_unique_id(),
            IssueInstant=issue_instant,
            Destination=logout_response_attrs.get('destination'),
            InResponseTo=logout_response_attrs.get('in_response_to')
        )
    )
    issuer_attrs = data.get('issuer').get('attrs')
    issuer = Issuer(
        attrib=dict(
            NameQualifier=issuer_attrs.get('name_qualifier'),
        ),
        text=data.get('issuer').get('text')
    )
    response.append(issuer)
    status = Status()
    status_code_value = response_status.get('status_code')
    status_code = StatusCode(
        attrib=dict(
            Value=status_code_value
        )
    )
    status.append(status_code)
    response.append(status)
    return response
