# coding: utf-8
import unittest

from testenv.translation import Libxml2Translator
from testenv.validators import ValidationDetail


class Libxml2ItalianTranslationTestCase(unittest.TestCase):
    samples = {
        ('PARSER', 'ERR_DOCUMENT_END',
         'Extra content at the end of the document'):
        'Contenuto extra alla fine del documento.',

        ('PARSER', 'ERR_DOCUMENT_EMPTY', 'Document is empty'):
        'Il documento è vuoto.',

        ('SCHEMASV', 'SCHEMAV_CVC_COMPLEX_TYPE_4',
         "Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest': "
         "The attribute 'IssueInstant' is required but missing."):
        "Elemento '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest': "
        "L'attributo 'IssueInstant' è mandatorio ma non presente.",

        ('SCHEMASV', 'SCHEMAV_CVC_DATATYPE_VALID_1_2_1',
         "Element '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', "
         "attribute 'ID': '123456' is not a valid value of the atomic type "
         "'xs:ID'."):
        "Elemento '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest', "
        "attributo 'ID': Il valore dell'attributo ID può iniziare solo con una lettera o con un underscore, "
        "e può contenere solo lettere, numeri, underscore, trattini e punti.",

        ('SCHEMASV', 'SCHEMAV_CVC_ENUMERATION_VALID',
         "Element '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext', "
         "attribute 'Comparison': [facet 'enumeration'] The value 'invalid' is "
         "not an element of the set {'exact', 'minimum', 'maximum', 'better'}."):
        "Elemento '{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext', "
        "attributo 'Comparison': [facet 'enumeration'] Il valore 'invalid' non è "
        "un elemento dell'insieme {'exact', 'minimum', 'maximum', 'better'}.",
    }

    def test_translations(self):
        translator = Libxml2Translator()
        for input_data, it_message in self.samples.items():
            domain, type_, en_message = input_data
            en_error = ValidationDetail(
                None, 1, 2, domain, type_, en_message, '')
            it_error = translator.translate(en_error)
            self.assertEqual(it_error.message, it_message)

    def test_multiple_error_translation(self):
        translator = Libxml2Translator()
        errors = [
            ValidationDetail(None, 1, 2, 'domain1', 'type1',
                             'an error occured', 'path1'),
            ValidationDetail(None, 3, 4, 'domain2', 'type2',
                             'another error occured', 'path2')
        ]
        actual = translator.translate_many(errors)
        self.assertEqual(actual, errors)
