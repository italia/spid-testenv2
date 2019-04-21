# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from copy import deepcopy
from datetime import datetime, timedelta
from hashlib import sha1
from uuid import uuid4

from lxml.builder import ElementMaker
from lxml.etree import tostring

from testenv.settings import (
    BINDING_HTTP_POST, DS, MD, NAME_FORMAT_BASIC, NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_TRANSIENT, NSMAP, SAML, SAMLP,
    SCM_BEARER, SPID_ATTRIBUTES, TIMEDELTA, VERSION, XS, XSI,
)

samlp_maker = ElementMaker(
    namespace=SAMLP,
    nsmap=dict(samlp=SAMLP),
)

saml_maker = ElementMaker(
    namespace=SAML,
    nsmap=dict(saml=SAML, xs=XS, xsi=XSI),
)

ds_maker = ElementMaker(
    namespace=DS,
    nsmap=dict(ds=DS),
)

md_maker = ElementMaker(
    namespace=MD,
    nsmap=dict(md=MD)
)

MAKERS = {
    'saml': saml_maker,
    'samlp': samlp_maker,
    'ds': ds_maker,
    'md': md_maker
}


class SamlMixin(object):
    saml_type = None
    defaults = {}

    def __init__(self, attrib={}, text=None, *args, **kwargs):
        E = MAKERS.get(self.saml_type)
        attributes = self.defaults.copy()
        attributes.update(attrib.copy())
        self._element = getattr(E, self.tag())(
            **attributes
        )
        if text is not None:
            self._element.text = text

    @property
    def class_name(self):
        return self.__class__.__name__

    def to_xml(self):
        return tostring(self.tree, pretty_print=True)

    @property
    def tree(self):
        return self._element

    def append(self, el):
        self.tree.append(el.tree)

    @classmethod
    def tag(cls):
        return '{%s}' % NSMAP[cls.saml_type] + cls.__name__


class Response(SamlMixin):
    saml_type = 'samlp'
    defaults = {
        'Version': VERSION
    }


class LogoutResponse(SamlMixin):
    saml_type = 'samlp'
    defaults = {
        'Version': VERSION
    }


class Assertion(SamlMixin):
    saml_type = 'saml'
    defaults = {
        'Version': VERSION
    }


class Issuer(SamlMixin):
    saml_type = 'saml'
    defaults = {
        'Format': NAMEID_FORMAT_ENTITY
    }


# AttributeStatement

class AttributeStatement(SamlMixin):
    saml_type = 'saml'


class Attribute(SamlMixin):
    saml_type = 'saml'
    defaults = {}


class AttributeValue(SamlMixin):
    saml_type = 'saml'

#####################


# AuthnStatement

class AuthnStatement(SamlMixin):
    saml_type = 'saml'


class AuthnContext(SamlMixin):
    saml_type = 'saml'


class AuthnContextClassRef(SamlMixin):
    saml_type = 'saml'

#####################


# AuthnStatement

class Conditions(SamlMixin):
    saml_type = 'saml'


class AudienceRestriction(SamlMixin):
    saml_type = 'saml'


class Audience(SamlMixin):
    saml_type = 'saml'

#####################


# Subject

class Subject(SamlMixin):
    saml_type = 'saml'


class NameID(SamlMixin):
    saml_type = 'saml'
    defaults = {
        'Format': NAMEID_FORMAT_TRANSIENT
    }


class SubjectConfirmation(SamlMixin):
    saml_type = 'saml'
    defaults = {
        'Method': SCM_BEARER
    }


class SubjectConfirmationData(SamlMixin):
    saml_type = 'saml'


#####################


# Subject

class Status(SamlMixin):
    saml_type = 'samlp'


class StatusCode(SamlMixin):
    saml_type = 'samlp'


class StatusDetail(SamlMixin):
    saml_type = 'samlp'


class StatusMessage(SamlMixin):
    saml_type = 'samlp'

#####################


class Signature(SamlMixin):
    saml_type = 'ds'


def generate_unique_id():
    '''
    Generates an ID string
    :return: A unique string
    :rtype: string
    '''
    return 'id_{}'.format(sha1(uuid4().hex.encode('utf-8')).hexdigest())


def generate_issue_instant():
    '''
    Generates an issue instant value
    '''
    issue_instant = datetime.utcnow()
    not_before = issue_instant - timedelta(minutes=TIMEDELTA)
    not_on_or_after = issue_instant + timedelta(minutes=TIMEDELTA)
    issue_instant = issue_instant.replace(microsecond=0)
    issue_instant = issue_instant.isoformat() + 'Z'
    not_before = not_before.replace(microsecond=0)
    not_before = not_before.isoformat() + 'Z'
    not_on_or_after = not_on_or_after.replace(microsecond=0)
    not_on_or_after = not_on_or_after.isoformat() + 'Z'
    return issue_instant, not_before, not_on_or_after


def create_logout_response(data, response_status):
    issue_instant, _, _ = generate_issue_instant()
    logout_response_attrs = data.get('logout_response').get('attrs')
    # Create a logout response
    response = LogoutResponse(
        attrib=dict(
            ID=generate_unique_id(),
            IssueInstant=issue_instant,
            Destination=logout_response_attrs.get('destination'),
            InResponseTo=logout_response_attrs.get('in_response_to')
        )
    )
    # Setup issuer data
    issuer_attrs = data.get('issuer').get('attrs')
    issuer = Issuer(
        attrib=dict(
            NameQualifier=issuer_attrs.get('name_qualifier'),
        ),
        text=data.get('issuer').get('text')
    )
    response.append(issuer)
    # Setup status data
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


def create_response(data, response_status, attributes={}, has_assertion=True):
    issue_instant, not_before, not_on_or_after = generate_issue_instant()
    response_attrs = data.get('response').get('attrs')
    # Create a response
    response = Response(
        attrib=dict(
            ID=generate_unique_id(),
            IssueInstant=issue_instant,
            Destination=response_attrs.get('destination'),
            InResponseTo=response_attrs.get('in_response_to')
        )
    )

    # Setup issuer data
    issuer_attrs = data.get('issuer').get('attrs')
    issuer = Issuer(
        attrib=dict(
            NameQualifier=issuer_attrs.get('name_qualifier'),
        ),
        text=data.get('issuer').get('text')
    )
    response.append(issuer)

    # Setup status data
    status = Status()
    status_code_value = response_status.get('status_code')
    status_code = StatusCode(
        attrib=dict(
            Value=status_code_value
        )
    )
    status.append(status_code)
    response.append(status)

    # Create and setup the assertion
    if has_assertion:
        assertion = Assertion(
            attrib=dict(
                ID=generate_unique_id(),
                IssueInstant=issue_instant,
            )
        )
        # Setup subject data
        subject = Subject()
        name_id_attrs = data.get('name_id').get('attrs')
        name_id = NameID(
            attrib=dict(
                NameQualifier=name_id_attrs.get('name_qualifier'),
            ),
            text=generate_unique_id()
        )
        subject.append(name_id)
        subject_confirmation = SubjectConfirmation()
        subject_confirmation_data_attrs = data.get(
            'subject_confirmation_data', {}).get('attrs', {})
        subject_confirmation_data_in_response_to = subject_confirmation_data_attrs.get(
            'in_response_to', response_attrs.get('in_response_to')
        )
        subject_confirmation_data_not_on_or_after = subject_confirmation_data_attrs.get(
            'not_on_or_after', not_on_or_after
        )
        subject_confirmation_data = SubjectConfirmationData(
            attrib=dict(
                Recipient=subject_confirmation_data_attrs.get('recipient'),
                NotOnOrAfter=subject_confirmation_data_not_on_or_after,
                InResponseTo=subject_confirmation_data_in_response_to
            )
        )
        subject_confirmation.append(subject_confirmation_data)
        subject.append(subject_confirmation)
        assertion.append(deepcopy(issuer))
        assertion.append(subject)
        # Setup conditions data
        conditions_attrs = data.get(
            'conditions', {}).get('attrs', {})
        conditions_not_before = conditions_attrs.get('not_before', not_before)
        conditions_not_on_or_after = conditions_attrs.get('not_on_or_after', not_on_or_after)
        conditions = Conditions(
            attrib=dict(
                NotBefore=conditions_not_before,
                NotOnOrAfter=conditions_not_on_or_after
            )
        )
        audience_restriction = AudienceRestriction()
        audience = Audience(text=data.get('audience').get('text'))
        audience_restriction.append(audience)
        conditions.append(audience_restriction)
        assertion.append(conditions)
        # Setup authn statement data
        # FIXME: handle SessionIndex for real
        authn_statement = AuthnStatement(
            attrib=dict(
                AuthnInstant=issue_instant,
                SessionIndex=generate_unique_id()
            )
        )
        authn_context = AuthnContext()
        authn_context_class_ref = AuthnContextClassRef(
            text=data.get('authn_context_class_ref').get('text')
        )
        authn_context.append(authn_context_class_ref)
        authn_statement.append(authn_context)
        assertion.append(authn_statement)
        # Setup attribute statement data (if attributes required)
        if attributes:
            attribute_statement = AttributeStatement()
            for attr, info in attributes.items():
                _attribute = Attribute(
                    attrib=dict(
                        Name=attr
                    )
                )
                _attribute_value = AttributeValue(
                    attrib={'{%s}type' % (XSI): 'xs:' + info[0]},
                    text=info[1]
                )
                _attribute.append(_attribute_value)
                attribute_statement.append(_attribute)
            assertion.append(attribute_statement)
        response.append(assertion)
    return response


def create_error_response(data, response_status):
    issue_instant, not_before, not_on_or_after = generate_issue_instant()
    response_attrs = data.get('response').get('attrs')
    # Create a response
    response = Response(
        attrib=dict(
            ID=generate_unique_id(),
            IssueInstant=issue_instant,
            Destination=response_attrs.get('destination'),
            InResponseTo=response_attrs.get('in_response_to')
        )
    )
    # Setup status data
    status = Status()
    status_code_value = response_status.get('status_code')
    status_message_text = response_status.get('status_message')
    status_message = StatusMessage(text=status_message_text)
    status_code = StatusCode(
        attrib=dict(
            Value=status_code_value
        )
    )
    status.append(status_code)
    status.append(status_message)
    response.append(status)
    # Setup issuer data
    issuer_attrs = data.get('issuer').get('attrs')
    issuer = Issuer(
        attrib=dict(
            NameQualifier=issuer_attrs.get('name_qualifier'),
        ),
        text=data.get('issuer').get('text')
    )
    response.append(issuer)
    return response


# Metadata

class EntityDescriptor(SamlMixin):
    saml_type = 'md'


class IDPSSODescriptor(SamlMixin):
    saml_type = 'md'
    defaults = {
        'protocolSupportEnumeration': SAMLP,
    }


class SPSSODescriptor(SamlMixin):
    saml_type = 'md'
    defaults = {
        'protocolSupportEnumeration': SAMLP,
    }


class NameIDFormat(SamlMixin):
    saml_type = 'md'


class KeyDescriptor(SamlMixin):
    saml_type = 'md'


class KeyInfo(SamlMixin):
    saml_type = 'ds'


class X509Data(SamlMixin):
    saml_type = 'ds'


class X509Certificate(SamlMixin):
    saml_type = 'ds'


class SingleSignOnService(SamlMixin):
    saml_type = 'md'


class SingleLogoutService(SamlMixin):
    saml_type = 'md'


class Organization(SamlMixin):
    saml_type = 'md'


class OrganizationName(SamlMixin):
    saml_type = 'md'


class OrganizationURL(SamlMixin):
    saml_type = 'md'


class AssertionConsumerService(SamlMixin):
    saml_type = 'md'
    defaults = {
        'Binding': BINDING_HTTP_POST
    }


class AttributeConsumingService(SamlMixin):
    saml_type = 'md'


class ServiceName(SamlMixin):
    saml_type = 'md'


class RequestedAttribute(SamlMixin):
    saml_type = 'md'


def create_idp_metadata(
    entity_id,
    want_authn_requests_signed,
    keys=None,
    single_sign_on_services=None,
    single_logout_services=None,
    attributes=None,
    org=None,
):
    entity_descriptor = EntityDescriptor(
        attrib=dict(
            entityID=entity_id
        )
    )
    # Setup idp sso descriptor
    idp_sso_descriptor = IDPSSODescriptor(
        attrib=dict(
            WantAuthnRequestsSigned=want_authn_requests_signed
        )
    )
    # Setup key descriptor(s)
    if keys is not None:
        for _key in keys:
            key_descriptor = KeyDescriptor(
                attrib=dict(
                    use=_key.use
                )
            )
            key_info = KeyInfo()
            x509_data = X509Data()
            x509_certificate = X509Certificate(
                text=_key.value
            )
            x509_data.append(x509_certificate)
            key_info.append(x509_data)
            key_descriptor.append(key_info)
            idp_sso_descriptor.append(key_descriptor)

    # setup single logout service(s)
    if single_logout_services is not None:
        for _slo in single_logout_services:
            single_logout_service = SingleLogoutService(
                attrib=dict(
                    Binding=_slo.binding,
                    Location=_slo.location
                )
            )
            idp_sso_descriptor.append(single_logout_service)

    # setup name id
    name_id_format = NameIDFormat(
        text=NAMEID_FORMAT_TRANSIENT
    )
    idp_sso_descriptor.append(name_id_format)

    # setup single sign on service(s)
    if single_sign_on_services is not None:
        for _sso in single_sign_on_services:
            single_sign_on_service = SingleSignOnService(
                attrib=dict(
                    Binding=_sso.binding,
                    Location=_sso.location
                )
            )
            idp_sso_descriptor.append(single_sign_on_service)

    # setup attributes
    if not attributes:
        attributes = list(SPID_ATTRIBUTES['primary'].keys())
        attributes.extend(list(SPID_ATTRIBUTES['secondary'].keys()))
    for attr_name in attributes:
        # if attr_name in SPID_ATTRIBUTES['primary']:
        #    attr_type = SPID_ATTRIBUTES['primary'][attr_name]
        # elif attr_name in SPID_ATTRIBUTES['secondary']:
        #    attr_type = SPID_ATTRIBUTES['secondary'][attr_name]
        # else:
        #    continue
        _attrib = {
            'Name': attr_name,
            # This does not pass XSD validation; it looks like an error in the spec
            # '{%s}type' % (XSI): 'xs:' + attr_type
        }
        attribute = Attribute(
            attrib=_attrib
        )
        idp_sso_descriptor.append(attribute)
    entity_descriptor.append(idp_sso_descriptor)
    if org is not None:
        organization = Organization()
        organization_name = OrganizationName(text=org.name)
        organization.append(organization_name)
        organization_url = OrganizationURL(text=org.url)
        organization.append(organization_url)
        entity_descriptor.append(organization)
    return entity_descriptor


def create_sp_metadata(
    entity_id,
    authn_request_signed,
    keys=None,
    assertion_consumer_services=None,
    attribute_consuming_services=None,
    single_logout_services=None,
    md_id=None,
    check_attributes=True,
    name_format=True
):
    _id = generate_unique_id() if md_id is None else md_id
    entity_descriptor = EntityDescriptor(
        attrib=dict(
            entityID=entity_id,
            ID=_id
        )
    )
    # Setup idp sso descriptor
    sp_sso_descriptor = SPSSODescriptor(
        attrib=dict(
            AuthnRequestsSigned=authn_request_signed
        )
    )
    if keys is not None:
        for _key in keys:
            key_descriptor = KeyDescriptor(
                attrib=dict(
                    use=_key.use
                )
            )
            key_info = KeyInfo()
            x509_data = X509Data()
            x509_certificate = X509Certificate(
                text=_key.value
            )
            x509_data.append(x509_certificate)
            key_info.append(x509_data)
            key_descriptor.append(key_info)
            sp_sso_descriptor.append(key_descriptor)
    # setup single logout service(s)
    if single_logout_services is not None:
        for _slo in single_logout_services:
            single_logout_service = SingleLogoutService(
                attrib=dict(
                    Binding=_slo.binding,
                    Location=_slo.location
                )
            )
            sp_sso_descriptor.append(single_logout_service)
    # setup name id
    name_id_format = NameIDFormat(
        text=NAMEID_FORMAT_TRANSIENT
    )
    sp_sso_descriptor.append(name_id_format)
    # Setup assertion consumer service(s)
    if assertion_consumer_services is not None:
        for idx, _ascs in enumerate(assertion_consumer_services):
            _attrib = dict(
                Location=_ascs.location,
                index=str(idx)
            )
            if idx == 0:
                _attrib['isDefault'] = 'true'
            assertion_consumer_service = AssertionConsumerService(
                attrib=_attrib
            )
            sp_sso_descriptor.append(assertion_consumer_service)
    # Setup attribute consuming service(s)
    if attribute_consuming_services is not None:
        for idx, _atcs in enumerate(attribute_consuming_services):
            attribute_consuming_service = AttributeConsumingService(
                attrib=dict(
                    index=str(idx)
                )
            )
            service_name = ServiceName(text=_atcs.service_name)
            attribute_consuming_service.append(service_name)
            for attr_name in _atcs.attributes:
                if attr_name in SPID_ATTRIBUTES[
                    'primary'
                ] or attr_name in SPID_ATTRIBUTES[
                    'secondary'
                ] or not check_attributes:
                    _attrib = {
                        'Name': attr_name
                    }
                    if name_format:
                        _attrib['NameFormat'] = NAME_FORMAT_BASIC
                    requested_attribute = RequestedAttribute(
                        attrib=_attrib
                    )
                    attribute_consuming_service.append(requested_attribute)
            sp_sso_descriptor.append(attribute_consuming_service)
    entity_descriptor.append(sp_sso_descriptor)
    return entity_descriptor
