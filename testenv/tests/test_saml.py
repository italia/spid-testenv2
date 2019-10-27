import unittest

from testenv.saml import create_idp_metadata, create_response
from testenv.settings import (
    BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, DS, MD, SAML, SAMLP, SPID_LEVEL_1, STATUS_SUCCESS,
)
from testenv.utils import Key, Slo, Sso

from .utils import validate_xml


class SamlElementTestCase(unittest.TestCase):

    def test_no_authenticating_authority_in_assertion(self):
        # See issue https://github.com/italia/spid-testenv2/issues/68
        response = create_response(
            {
                'response': {
                    'attrs': {
                        'in_response_to': 'test_12345',
                        'destination': 'http://some.dest.nation'
                    }
                },
                'issuer': {
                    'attrs': {
                        'name_qualifier': 'http://test_id.entity',
                    },
                    'text': 'http://test_id.entity'
                },
                'name_id': {
                    'attrs': {
                        'name_qualifier': 'http://test_id.entity',
                    }
                },

                'subject_confirmation_data': {
                    'attrs': {
                        'recipient': 'http://test_id.entity',
                    }
                },
                'audience': {
                    'text': 'http://test_sp_id.entity',
                },
                'authn_context_class_ref': {
                    'text': SPID_LEVEL_1
                }
            },
            {
                'status_code': STATUS_SUCCESS
            },
            {}
        )
        authenticating_authorities = response._element.findall(
            './/{%s}AuthenticatingAuthority' % SAML)
        self.assertEqual(len(authenticating_authorities), 0)

    def test_issuer_in_response_and_assertion(self):
        # https://github.com/italia/spid-testenv2/issues/145
        response = create_response(
            {
                'response': {
                    'attrs': {
                        'in_response_to': 'test_12345',
                        'destination': 'http://some.dest.nation'
                    }
                },
                'issuer': {
                    'attrs': {
                        'name_qualifier': 'http://test_id.entity',
                    },
                    'text': 'http://test_id.entity'
                },
                'name_id': {
                    'attrs': {
                        'name_qualifier': 'http://test_id.entity',
                    }
                },

                'subject_confirmation_data': {
                    'attrs': {
                        'recipient': 'http://test_id.entity',
                    }
                },
                'audience': {
                    'text': 'http://test_sp_id.entity',
                },
                'authn_context_class_ref': {
                    'text': SPID_LEVEL_1
                }
            },
            {
                'status_code': STATUS_SUCCESS
            },
            {}
        )
        issuers = response._element.findall('.//{%s}Issuer' % SAML)
        self.assertEqual(len(issuers), 2)
        for issuer in issuers:
            self.assertEqual(issuer.get('NameQualifier'),
                             'http://test_id.entity')
            self.assertEqual(issuer.text, 'http://test_id.entity')
        self.assertEqual(issuers[0].getparent().tag, '{%s}Response' % SAMLP)
        self.assertEqual(issuers[1].getparent().tag, '{%s}Assertion' % SAML)

        self.assertTrue(validate_xml(response.to_xml(), 'testenv/xsd/saml-schema-protocol-2.0.xsd'),
                        "The resulting XML is invalid")

    def test_session_index_in_response(self):
        # https://github.com/italia/spid-testenv2/issues/160
        response = create_response(
            {
                'response': {
                    'attrs': {
                        'in_response_to': 'test_8989',
                        'destination': 'http://des.nation'
                    }
                },
                'issuer': {
                    'attrs': {
                        'name_qualifier': 'http://test_id2.entity',
                    },
                    'text': 'http://test_id2.entity'
                },
                'name_id': {
                    'attrs': {
                        'name_qualifier': 'http://test_id2.entity',
                    }
                },

                'subject_confirmation_data': {
                    'attrs': {
                        'recipient': 'http://test_id2.entity',
                    }
                },
                'audience': {
                    'text': 'http://test_sp_id2.entity',
                },
                'authn_context_class_ref': {
                    'text': SPID_LEVEL_1
                }
            },
            {
                'status_code': STATUS_SUCCESS
            },
            {}
        )
        authn_statements = response._element.findall(
            './/{%s}AuthnStatement' % SAML)
        self.assertEqual(len(authn_statements), 1)
        authn_statement = authn_statements[0]
        self.assertTrue(authn_statement.get('SessionIndex', False))
        self.assertTrue(validate_xml(response.to_xml(), 'testenv/xsd/saml-schema-protocol-2.0.xsd'),
                        "The resulting XML is invalid")

    def test_idp_metadata(self):
        ssos = [Sso(binding=BINDING_HTTP_POST, location='http://sso.sso')]
        slos = [Slo(binding=BINDING_HTTP_REDIRECT, location='http://slo.slo')]
        metadata = create_idp_metadata(
            entity_id='test_id123',
            want_authn_requests_signed='true',
            keys=[Key(use='signing', value='CERTCERTCERT')],
            single_sign_on_services=ssos,
            single_logout_services=slos
        )
        x509_cert = metadata._element.findall('.//{%s}X509Certificate' % DS)
        self.assertEqual(len(x509_cert), 1)
        self.assertEqual(x509_cert[0].text, 'CERTCERTCERT')
        ssos = metadata._element.findall('.//{%s}SingleSignOnService' % MD)
        self.assertEqual(ssos[0].attrib['Binding'], BINDING_HTTP_POST)
        self.assertEqual(ssos[0].attrib['Location'], 'http://sso.sso')
        self.assertEqual(len(ssos), 1)
        slos = metadata._element.findall('.//{%s}SingleLogoutService' % MD)
        self.assertEqual(len(slos), 1)
        self.assertEqual(slos[0].attrib['Binding'], BINDING_HTTP_REDIRECT)
        self.assertEqual(slos[0].attrib['Location'], 'http://slo.slo')
