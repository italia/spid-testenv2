
# -*- coding: utf-8 -*-
import os
import os.path
import shutil
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

import flask
from freezegun import freeze_time
from OpenSSL import crypto
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.saml import NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_TRANSIENT

sys.path.insert(0, '../')
spid_testenv = __import__("spid-testenv")

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

DATA_DIR = 'tests/data/'


def generate_certificate(fname, path=DATA_DIR):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')
    open(os.path.join(path, '{}.crt'.format(fname)), "wb").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(os.path.join(path, '{}.key'.format(fname)), "wb").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


def generate_authn_request(data={}):
    version = data.get('version') if data.get('version') else '2.0'
    issue_instant = data.get('issue_instant') if data.get('issue_instant') else '2018-07-16T09:38:29Z'
    destination = data.get('destination') if data.get('destination') else 'http://spid-testenv:8088/sso-test'
    protocol_binding = data.get('protocol_binding') if data.get('protocol_binding') else BINDING_HTTP_POST
    acs = data.get('assertion_consumer_service_url') if data.get('assertion_consumer_service_url') else 'https://spid.test:8000/acs-test'
    issuer__format = data.get('issuer__format') if data.get('issuer__format') else NAMEID_FORMAT_ENTITY
    issuer_url = data.get('issuer__url') if data.get('issuer__url') else 'https://spid.test:8000'
    name_id_policy__format = data.get('name_id_policy__format') if data.get('name_id_policy__format') else NAMEID_FORMAT_TRANSIENT
    requested_authn_context__comparison = data.get('requested_authn_context__comparison') if data.get('requested_authn_context__comparison') else 'exact'
    requested_authn_context__authn_context_class_ref = data.get('requested_authn_context__authn_context_class_ref') if data.get('requested_authn_context__authn_context_class_ref') else 'https://www.spid.gov.it/SpidL1'


    xmlstr = '''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="12456"
                    Version="%s"
                    IssueInstant="%s"
                    Destination="%s"
                    ProtocolBinding="%s"
                    AssertionConsumerServiceURL="%s">
        <saml:Issuer Format="%s"
                    NameQualifier="%s">%s</saml:Issuer>
        <samlp:NameIDPolicy Format="%s" />
        <samlp:RequestedAuthnContext Comparison="%s">
            <saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
    ''' % (
        version,
        issue_instant,
        destination,
        protocol_binding,
        acs,
        issuer__format,
        issuer_url,
        issuer_url,
        name_id_policy__format,
        requested_authn_context__comparison,
        requested_authn_context__authn_context_class_ref
    )
    return bytes(xmlstr.encode('utf-8'))


class SpidTestenvTest(unittest.TestCase): 

    maxDiff = None


    @classmethod
    def setUpClass(cls):
        generate_certificate(fname='idp')
        generate_certificate(fname='sp')
        example_metadata = os.path.join(DATA_DIR, 'sp-metadata.xml.example')
        sp_cert = os.path.join(DATA_DIR, 'sp.crt')
        tmp_metadata = os.path.join(DATA_DIR, 'sp-metadata.xml')
        shutil.copyfile(
            example_metadata,
            tmp_metadata
        )
        xml = ET.parse(tmp_metadata)
        with open(sp_cert, 'r') as f:
            cert_value = ''.join(f.readlines()[1:-1])
            for cert in xml.findall('//{http://www.w3.org/2000/09/xmldsig#}X509Certificate'):
                cert.text = cert_value
        xml.write(tmp_metadata)
        app = flask.Flask(spid_testenv.__name__, static_url_path='/static')
        _config = spid_testenv._get_config('tests/data/config.yaml')
        cls.idp_server = spid_testenv.IdpServer(app=app, config=_config)
        cls.idp_server.app.testing = True
        cls.test_client = cls.idp_server.app.test_client()

    @classmethod
    def tearDownClass(cls):
        to_remove = ['users.json', 'idp.crt', 'idp.key', 'sp.crt', 'sp.key', 'sp-metadata.xml']
        for f in to_remove:
            os.remove(os.path.join(DATA_DIR, f))

    def setUp(self):
        pass 

    def tearDown(self):
        self.idp_server.ticket = {}
        self.idp_server.responses = {}
        self.idp_server.challenges = {}

    def test_permissions(self):
        response = self.test_client.get('/login')
        self.assertEqual(response.status_code, 403)
        response = self.test_client.post('/continue-response')
        self.assertEqual(response.status_code, 400)
        response = self.test_client.post('/continue-response', data={'request_key': 'somevalue'})
        self.assertEqual(response.status_code, 403)
        response = self.test_client.get('/users')
        self.assertEqual(response.status_code, 200)
        response = self.test_client.post('/users', data={})
        self.assertEqual(response.status_code, 400)
        response = self.test_client.get('/metadata')
        self.assertEqual(response.status_code, 200)

    def test_authnrequest_no_SAML_parameter(self):
        response = self.test_client.get('/sso-test')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Parametro SAMLRequest assente.', response.get_data())

    @freeze_time("2018-07-16T10:38:29Z")
    @patch('spid-testenv.SpidServer.unravel', return_value=generate_authn_request())
    def test_issue_instant_out_of_range(self, unravel):
        response = self.test_client.get('/sso-test?SAMLRequest=b64encodedrequest')
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            u'2018-07-16 09:38:29 non è compreso tra 2018-07-16 10:36:29 e 2018-07-16 10:40:29',
            response_text
        )
        self.assertNotIn(
            u'la data non è in formato UTC',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('spid-testenv.SpidServer.unravel', return_value=generate_authn_request())
    @patch('spid-testenv.verify_redirect_signature', return_value=True)
    def test_issue_instant_out_of_range(self, unravel, verified):
        response = self.test_client.get(
            u'/sso-test?SAMLRequest=b64encodedrequest&SigAlg=alg&Signature=sign',
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            u'2018-07-16 09:38:29 non è compreso tra 2018-07-16 09:36:29 e 2018-07-16 09:40:29',
            response_text
        )
        self.assertNotIn(
            u'la data non è in formato UTC',
            response_text
        )

    @freeze_time("2018-07-11T07:28:29Z")
    @patch('spid-testenv.SpidServer.unravel', return_value=generate_authn_request({'issue_instant': '2018-07-11T07:28:57.935Z'}))
    @patch('spid-testenv.verify_redirect_signature', return_value=True)
    def test_issue_instant_ms(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg=alg&Signature=sign',
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            u'2018-07-16 09:38:29 non è compreso tra 2018-07-16 09:36:29 e 2018-07-16 09:40:29',
            response_text
        )
        self.assertNotIn(
            u'la data non è in formato UTC',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('spid-testenv.SpidServer.unravel', return_value=generate_authn_request({'protocol_binding': BINDING_HTTP_REDIRECT}))
    @patch('spid-testenv.verify_redirect_signature', return_value=True)
    def test_wrong_protocol_binding(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg=alg&Signature=sign',
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            u'{} è diverso dal valore di riferimento {}'.format(BINDING_HTTP_REDIRECT, BINDING_HTTP_POST),
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('spid-testenv.SpidServer.unravel', return_value=generate_authn_request({'protocol_binding': BINDING_HTTP_POST}))
    @patch('spid-testenv.verify_redirect_signature', return_value=True)
    def test_right_protocol_binding(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg=alg&Signature=sign',
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            u'{} è diverso dal valore di riferimento {}'.format(BINDING_HTTP_REDIRECT, BINDING_HTTP_POST),
            response_text
        )

if __name__ == '__main__':
    unittest.main()
