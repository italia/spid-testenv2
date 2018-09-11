
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import base64
import os
import os.path
import shutil
import sys
import unittest

import flask
from bs4 import BeautifulSoup as BS
from freezegun import freeze_time
from lxml import etree as ET
from OpenSSL import crypto
from six.moves.urllib.parse import parse_qs, quote, urlparse

from testenv import config
from testenv.crypto import decode_base64_and_inflate, deflate_and_base64_encode, sign_http_redirect
from testenv.parser import SAMLTree
from testenv.settings import (
    BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, NAMEID_FORMAT_ENTITY, NAMEID_FORMAT_TRANSIENT, SIG_RSA_SHA1,
    SIG_RSA_SHA256,
)

sys.path.insert(0, '../')
spid_testenv = __import__("spid-testenv")

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


DATA_DIR = 'testenv/tests/data/'


def _sp_single_logout_service(server, issuer_name, binding):
    _slo = server.metadata.single_logout_service(
        issuer_name, binding=binding, typ='spsso'
    )
    return _slo


def generate_certificate(fname, path=DATA_DIR):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    cert = crypto.X509()
    cert.get_subject().C = 'IT'
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_pubkey(key)
    cert.sign(key, str('sha256'))
    open(os.path.join(path, '{}.crt'.format(fname)), "wb").write(
        crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open(os.path.join(path, '{}.key'.format(fname)), "wb").write(
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


def generate_authn_request(data={}, acs_level=0):
    _id = data.get('id') if data.get('id') else 'test_123456'
    version = data.get('version') if data.get('version') else '2.0'
    issue_instant = data.get('issue_instant') if data.get('issue_instant') else '2018-07-16T09:38:29Z'
    destination = data.get('destination') if data.get('destination') else 'http://spid-testenv:8088'
    protocol_binding = data.get('protocol_binding') if data.get('protocol_binding') else BINDING_HTTP_POST
    acsi = data.get('assertion_consumer_service_index') if data.get('assertion_consumer_service_index') else '1'
    acsu = data.get('assertion_consumer_service_url') if data.get('assertion_consumer_service_url') else 'https://spid.test:8000/acs-test'
    issuer__format = data.get('issuer__format') if data.get('issuer__format') else NAMEID_FORMAT_ENTITY
    issuer_url = data.get('issuer__url') if data.get('issuer__url') else 'https://spid.test:8000'
    issuer__namequalifier = data.get('issuer__namequalifier') if data.get('issuer__namequalifier') else issuer_url
    name_id_policy__format = data.get('name_id_policy__format') if data.get('name_id_policy__format') else NAMEID_FORMAT_TRANSIENT
    requested_authn_context__comparison = data.get('requested_authn_context__comparison') if data.get('requested_authn_context__comparison') else 'exact'
    requested_authn_context__authn_context_class_ref = data.get('requested_authn_context__authn_context_class_ref') if data.get('requested_authn_context__authn_context_class_ref') else 'https://www.spid.gov.it/SpidL1'

    if acs_level == 0:
        _acs = '''
            ProtocolBinding="%s"
            AssertionConsumerServiceURL="%s"
        ''' % (protocol_binding, acsu)
    elif acs_level == 1:
        _acs = '''
            AssertionConsumerServiceIndex="%s"
        '''  % (acsi)
    elif acs_level == 2:
        _acs = '''
            ProtocolBinding="%s"
            AssertionConsumerServiceURL="%s"
            AssertionConsumerServiceIndex="%s"
        '''  % (protocol_binding, acsu, acsi)
    else:
        _acs = ''

    xmlstr = '''<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="%s"
                    Version="%s"
                    IssueInstant="%s"
                    Destination="%s"
                    %s>
        <saml:Issuer Format="%s"
                    NameQualifier="%s">%s</saml:Issuer>
        <samlp:NameIDPolicy Format="%s" />
        <samlp:RequestedAuthnContext Comparison="%s">
            <saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>
        </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
    ''' % (
        _id,
        version,
        issue_instant,
        destination,
        _acs,
        issuer__format,
        issuer__namequalifier,
        issuer_url,
        name_id_policy__format,
        requested_authn_context__comparison,
        requested_authn_context__authn_context_class_ref
    )
    return bytes(xmlstr.encode('utf-8'))


def generate_logout_request(data={}):
    _id = data.get('id') if data.get('id') else 'test_123456'
    version = data.get('version') if data.get('version') else '2.0'
    issue_instant = data.get('issue_instant') if data.get('issue_instant') else '2018-07-16T09:38:29Z'
    destination = data.get('destination') if data.get('destination') else 'http://spid-testenv:8088'
    issuer__format = data.get('issuer__format') if data.get('issuer__format') else NAMEID_FORMAT_ENTITY
    issuer_url = data.get('issuer__url') if data.get('issuer__url') else 'https://spid.test:8000'
    issuer__namequalifier = data.get('issuer__namequalifier') if data.get('issuer__namequalifier') else issuer_url
    name_id__format = data.get('name_id__format') if data.get('name_id__format') else NAMEID_FORMAT_TRANSIENT
    name_id__namequalifier = data.get('name_id__namequalifier') if data.get('name_id__namequalifier') else 'https://spid.test:8000'
    name_id__value = data.get('name_id__value') if data.get('name_id__value') else 'name_id'
    session_index__value = data.get('session_index__value') if data.get('session_index__value') else 'session_idx_123'

    xmlstr= '''<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="%s"
                Version="%s"
                IssueInstant="%s"
                Destination="%s">
        <saml:Issuer Format="%s" NameQualifier="%s">%s</saml:Issuer>
        <saml:NameID Format="%s" NameQualifier="%s">%s</saml:NameID>
        <samlp:SessionIndex>%s</samlp:SessionIndex>
        </samlp:LogoutRequest>
    ''' % (
        _id,
        version,
        issue_instant,
        destination,
        issuer__format,
        issuer__namequalifier,
        issuer_url,
        name_id__format,
        name_id__namequalifier,
        name_id__value,
        session_index__value
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
        config.load('testenv/tests/data/config.yaml')
        cls.idp_server = spid_testenv.IdpServer(app=app)
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
        self.assertIn(b'Dato mancante nella request: &#39;SAMLRequest&#39;', response.get_data())

    @freeze_time("2018-07-16T10:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_issue_instant_out_of_range(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            '2018-07-16 09:38:29 non è compreso tra 2018-07-16 10:36:29 e 2018-07-16 10:40:29',
            response_text
        )
        self.assertNotIn(
            'la data non è in formato UTC',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_issue_instant_ok(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            '2018-07-16 09:38:29 non è compreso tra 2018-07-16 09:36:29 e 2018-07-16 09:40:29',
            response_text
        )
        self.assertNotIn(
            'la data non è in formato UTC',
            response_text
        )

    @freeze_time("2018-07-11T07:28:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request({'issue_instant': '2018-07-11T07:28:57.935Z'}))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_issue_instant_ms(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            '2018-07-16 09:38:29 non è compreso tra 2018-07-16 09:36:29 e 2018-07-16 09:40:29',
            response_text
        )
        self.assertNotIn(
            'la data non è in formato UTC',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request({'protocol_binding': BINDING_HTTP_REDIRECT}))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_wrong_protocol_binding(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'è diverso dal valore di riferimento {}'.format(BINDING_HTTP_POST),
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request({'protocol_binding': BINDING_HTTP_POST}))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_right_protocol_binding(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            '{} è diverso dal valore di riferimento {}'.format(BINDING_HTTP_REDIRECT, BINDING_HTTP_POST),
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_no_assertion_consumer_service_index(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            'Uno e uno solo uno tra gli attributi o gruppi di attributi devono essere presenti: [AssertionConsumerServiceIndex, [AssertionConsumerServiceUrl, ProtocolBinding]]',            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(acs_level=1))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_no_assertion_consumer_service_url_and_protocol_binding(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            'Uno e uno solo uno tra gli attributi o gruppi di attributi devono essere presenti: [AssertionConsumerServiceIndex, [AssertionConsumerServiceUrl, ProtocolBinding]]',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(acs_level=2))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_all_assertion_consumer_service_attributes(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Uno e uno solo uno tra gli attributi o gruppi di attributi devono essere presenti: [AssertionConsumerServiceIndex, [AssertionConsumerServiceUrl, ProtocolBinding]]',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(acs_level=3))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_no_assertion_consumer_service_attributes(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Uno e uno solo uno tra gli attributi o gruppi di attributi devono essere presenti: [AssertionConsumerServiceIndex, [AssertionConsumerServiceUrl, ProtocolBinding]]',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    def test_wrong_signature_algorithm(self, unravel):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA1)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            "L&#39;algoritmo &#39;{}&#39; è considerato deprecato.".format(SIG_RSA_SHA1),
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_right_signature_algorithm(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            '{} non è supportato.'.format(SIG_RSA_SHA256),
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_in_response_to(self, unravel, verified):
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response = self.test_client.post(
            '/login',
            data={
                'confirm': 1,
                'username': 'test',
                'password': 'test'
            },
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertEqual(len(self.idp_server.ticket), 1)
        key = list(self.idp_server.ticket.keys())[0]
        authn_request = self.idp_server.ticket[key]
        old_in_response_to = authn_request.id
        self.assertIn(
            'InResponseTo=&#34;{}&#34;'.format(old_in_response_to),
            response_text
        )
        response = self.test_client.post(
            '/continue-response',
            data={
                'confirm': 1,
                'request_key': key
            },
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        with patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value = generate_authn_request({'id': 'test_9999'})) as mocked:
            response = self.test_client.get(
                '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            response = self.test_client.post(
                '/login',
                data={
                    'confirm': 1,
                    'username': 'test',
                    'password': 'test'
                },
                follow_redirects=True
            )
            self.assertEqual(response.status_code, 200)
            response_text = response.get_data(as_text=True)
            self.assertEqual(len(self.idp_server.ticket), 1)
            key = list(self.idp_server.ticket.keys())[0]
            authn_request = self.idp_server.ticket[key]
            in_response_to = authn_request.id
            self.assertNotEqual(old_in_response_to, in_response_to)
            self.assertIn(
                'InResponseTo=&#34;{}&#34;'.format(in_response_to),
                response_text
            )
            self.assertNotIn(
                'InResponseTo=&#34;{}&#34;'.format(old_in_response_to),
                response_text
            )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(data={'assertion_consumer_service_index': '12345'}, acs_level=1))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_wrong_assertion_consumer_service_index(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            "12345 non corrisponde a nessuno dei valori contenuti in [&#39;0&#39;]",
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(data={'assertion_consumer_service_index': '0'}, acs_level=1))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_right_assertion_consumer_service_index(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertNotIn(
            "non corrisponde a nessuno dei valori contenuti in",
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(data={'assertion_consumer_service_index': '0'}, acs_level=1))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_ensure_correct_redirect_url(self, unravel, verified):
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=False
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers['Location'], 'http://localhost/login')
        response = self.test_client.post(
            '/login',
            data={
                'confirm': 1,
                'username': 'test',
                'password': 'test'
            },
            follow_redirects=False
        )
        response_text = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        key = list(self.idp_server.ticket.keys())[0]
        response = self.test_client.post(
            '/continue-response',
            data={
                'confirm': 1,
                'request_key': key
            },
            follow_redirects=False
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            '<form action="http://127.0.0.1:8000/acs-test" method="post">',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_missing_samlrequest_parameter(self, unravel, verified):
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=False
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Dato mancante nella request: &#39;SAMLRequest&#39;',
            response_text
        )
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    def test_authn_request_http_redirect_bad_signature(self):
        xml_message = generate_authn_request()
        encoded_message = deflate_and_base64_encode(xml_message)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?SAMLRequest={}&SigAlg={}&Signature=sign'.format(quote(encoded_message), quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Verifica della firma fallita.',
            response_text
        )
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    def test_authn_request_http_redirect_missing_signature_parameter(self):
        # See: https://github.com/italia/spid-testenv2/issues/36
        xml_message = generate_authn_request()
        encoded_message = deflate_and_base64_encode(xml_message)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?SAMLRequest={}&SigAlg={}'.format(quote(encoded_message), quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Dato mancante nella request: &#39;Signature&#39;',
            response_text
        )
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    def test_authn_request_http_redirect_missing_sigalg_parameter(self):
        # See: https://github.com/italia/spid-testenv2/issues/36
        xml_message = generate_authn_request()
        encoded_message = deflate_and_base64_encode(xml_message)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?SAMLRequest={}&Signature={}'.format(quote(encoded_message), quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Dato mancante nella request: &#39;SigAlg&#39;',
            response_text
        )
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    def test_authn_request_http_redirect_missing_sigalg_and_signature_parameter(self):
        # See: https://github.com/italia/spid-testenv2/issues/36
        xml_message = generate_authn_request()
        encoded_message = deflate_and_base64_encode(xml_message)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?SAMLRequest={}'.format(quote(encoded_message), quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'Dato mancante nella request: &#39;SigAlg&#39;',
            response_text
        )
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    def test_authn_request_http_redirect_right_signature(self):
        xml_message = generate_authn_request()
        pkey = open(os.path.join(DATA_DIR, 'sp.key'), 'rb').read()
        query_string = sign_http_redirect(xml_message, pkey, req_type='SAMLRequest')
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response = self.test_client.get(
            '/sso-test?{}'.format(query_string),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            '<form class="Form Form--spaced u-margin-bottom-l " name="login" method="post" action="/login">',
            response_text
        )
        self.assertEqual(len(self.idp_server.ticket), 1)
        self.assertEqual(len(self.idp_server.responses), 0)
        key = list(self.idp_server.ticket.keys())[0]
        xmlstr = SAMLTree(self.idp_server.ticket[key]._xml_doc)
        xml_message = ET.fromstring(xml_message)
        xml_message = SAMLTree(xml_message)
        self.assertEqual(xml_message.id, xmlstr.id)

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(data={'issuer__url': 'https://something.spid.test'}, acs_level=1))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_wrong_issuer(self, unravel, verified):
        # See: https://github.com/italia/spid-testenv2/issues/42
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'entity ID https://something.spid.test non registrato',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_authn_request(data={'issuer__namequalifier': 'https://something.spid.test'}, acs_level=1))
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_wrong_issuer_namequalifier(self, unravel, verified):
        # See: https://github.com/italia/spid-testenv2/issues/77
        response = self.test_client.get(
            '/sso-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.idp_server.ticket), 0)
        self.assertEqual(len(self.idp_server.responses), 0)
        response_text = response.get_data(as_text=True)
        self.assertIn(
            'https://something.spid.test è diverso dal valore di riferimento https://spid.test:8000',
            response_text
        )

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_logout_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_logout_response_http_redirect(self, unravel, verified):
        # See: https://github.com/italia/spid-testenv2/issues/88
        with patch('testenv.server.IdpServer._sp_single_logout_service', return_value=_sp_single_logout_service(self.idp_server.server, 'https://spid.test:8000', BINDING_HTTP_REDIRECT)) as mocked:
            response = self.test_client.get(
                '/slo-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
                follow_redirects=False
            )
            self.assertEqual(response.status_code, 302)
            response_location = response.headers.get('Location')
            url = urlparse(response_location)
            query = parse_qs(url.query)
            self.assertIn(
                'Signature',
                query
            )
            saml_response = query.get('SAMLResponse')[0]
            response = decode_base64_and_inflate(saml_response)
            xml = ET.fromstring(response)
            signatures = xml.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            self.assertEqual(0, len(signatures))
            self.assertEqual(len(self.idp_server.ticket), 0)
            self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPRedirectRequestParser._decode_saml_request', return_value=generate_logout_request())
    @patch('testenv.crypto.HTTPRedirectSignatureVerifier.verify', return_value=True)
    def test_logout_response_http_post(self, unravel, verified):
        # See: https://github.com/italia/spid-testenv2/issues/88
        with patch('testenv.server.IdpServer._sp_single_logout_service', return_value=_sp_single_logout_service(self.idp_server.server, 'https://spid.test:8000', BINDING_HTTP_POST)) as mocked:
            response = self.test_client.get(
                '/slo-test?SAMLRequest=b64encodedrequest&SigAlg={}&Signature=sign'.format(quote(SIG_RSA_SHA256)),
                follow_redirects=False
            )
            self.assertEqual(response.status_code, 200)
            response_text = response.get_data(as_text=True)
            soup = BS(response_text)
            saml_response = soup.find('input', {'name': 'SAMLResponse'}).get('value')
            response = base64.b64decode(saml_response)
            xml = ET.fromstring(response)
            signatures = xml.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
            self.assertEqual(1, len(signatures))
            self.assertEqual(len(self.idp_server.ticket), 0)
            self.assertEqual(len(self.idp_server.responses), 0)

    @freeze_time("2018-07-16T09:38:29Z")
    @patch('testenv.parser.HTTPPostRequestParser._decode_saml_request', return_value=generate_authn_request())
    @patch('testenv.crypto.HTTPPostSignatureVerifier.verify', return_value=True)
    def test_relaystate_in_post_request_to_sp(self, verified, unravel):
        # https://github.com/italia/spid-testenv2/issues/135
        response = self.test_client.post(
            '/sso-test',
            data={
                'SAMLRequest': 'whatever',
                'RelayState': 'sp_relay_state_value',
            },
            follow_redirects=True,
        )
        response = self.test_client.post(
            '/login',
            data={
                'confirm': 1,
                'username': 'test',
                'password': 'test'
            },
            follow_redirects=True
        )
        key = list(self.idp_server.ticket.keys())[0]
        response = self.test_client.post(
            '/continue-response',
            data={
                'confirm': 1,
                'request_key': key
            },
            follow_redirects=False
        )
        response_text = response.get_data(as_text=True)
        self.assertIn('sp_relay_state_value', response_text)

if __name__ == '__main__':
    unittest.main()
