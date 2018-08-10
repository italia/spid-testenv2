import unittest

from testenv.parser import XMLValidator
from testenv.tests.data import sample_saml_requests as sample_requests


class FakeTranslator(object):

    def translate_many(self, errors):
        return errors


class AuthnRequestValidationTestCase(unittest.TestCase):

    def test_valid_requests(self):
        validator = XMLValidator(translator=FakeTranslator())
        for request in sample_requests.valid:
            errors = validator.validate_request(request)
            self.assertEqual(errors, [])

    def test_empty_request(self):
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request('')
        self.assertEqual(len(errors), 1)
        self.assertIn('Document is empty', errors[0].message)

    def test_not_xml(self):
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request('{"this": "is JSON"}')
        self.assertEqual(len(errors), 1)
        self.assertIn("Start tag expected, '<' not found", errors[0].message)

    def test_invalid_xml(self):
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request('<a></b>')
        self.assertEqual(len(errors), 1)
        self.assertIn(
            'Opening and ending tag mismatch: a line 1 and b',
            errors[0].message
        )

    def test_invalid_attribute_format(self):
        # See: https://github.com/italia/spid-testenv2/issues/63
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request(sample_requests.invalid_id_attr)
        self.assertEqual(len(errors), 1)
        self.assertIn(
            "is not a valid value of the atomic type 'xs:ID'",
            errors[0].message
        )

    def test_missing_mandatory_attribute(self):
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request(
            sample_requests.missing_issue_instant_attr)
        self.assertEqual(len(errors), 1)
        self.assertIn(
            "The attribute 'IssueInstant' is required but missing.",
            errors[0].message
        )

    def test_duplicate_attribute(self):
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request(
            sample_requests.duplicate_version_attr)
        self.assertEqual(len(errors), 1)
        self.assertIn('Attribute Version redefined', errors[0].message)

    def test_multiple_errors(self):
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request(sample_requests.multiple_errors)
        self.assertEqual(len(errors), 2)
        self.assertIn(
            "is not a valid value of the atomic type 'xs:ID'",
            errors[0].message
        )
        self.assertIn(
            "The attribute 'Version' is required but missing.",
            errors[1].message
        )

    def test_unexpected_element(self):
        # See: https://github.com/italia/spid-testenv2/issues/79
        validator = XMLValidator(translator=FakeTranslator())
        errors = validator.validate_request(sample_requests.unexpected_element)
        self.assertEqual(len(errors), 1)
        self.assertIn(
            "Element '{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef': "
            "This element is not expected. Expected is one of ( {urn:oasis:names:tc:SAML:2.0:assertion}"
            "Conditions, {urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext, {urn:oasis:names:tc:SAML:2.0:protocol}Scoping ).",
            errors[0].message
        )
