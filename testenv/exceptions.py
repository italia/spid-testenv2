# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class TestenvError(Exception):
    """Base exception class"""


class BadConfiguration(TestenvError):
    pass


class RequestParserError(TestenvError):
    pass


class DeserializationError(TestenvError):
    def __init__(self, errors):
        super(DeserializationError, self).__init__()
        self.errors = errors


class ValidationError(TestenvError):
    """Base validation error class"""

    def __init__(self, errors):
        super(ValidationError, self).__init__()
        self.errors = errors


class XMLFormatValidationError(ValidationError):
    pass


class SPIDValidationError(ValidationError):
    pass


class XMLSchemaValidationError(ValidationError):
    pass


class SignatureValidationError(ValidationError):
    pass


class StopValidation(TestenvError):
    pass
