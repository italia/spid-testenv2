# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import unittest

from lxml import etree

from testenv.saml import create_response
from testenv.settings import SAML, SPID_LEVEL_1, STATUS_SUCCESS


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
