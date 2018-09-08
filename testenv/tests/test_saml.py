# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

from lxml import etree

from testenv.saml import create_response
from testenv.settings import SAML, SAMLP, SPID_LEVEL_1, STATUS_SUCCESS

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
        authenticating_authorities = response._element.findall('.//{%s}AuthenticatingAuthority' % SAML)
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
            self.assertEqual(issuer.get('NameQualifier'), 'http://test_id.entity')
            self.assertEqual(issuer.text, 'http://test_id.entity')
        self.assertEqual(issuers[0].getparent().tag, '{%s}Response' % SAMLP)
        self.assertEqual(issuers[1].getparent().tag, '{%s}Assertion' % SAML)

        self.assertTrue(validate_xml(response.to_xml(), 'testenv/xsd/saml-schema-protocol-2.0.xsd'),
                        "The resulting XML is invalid")
