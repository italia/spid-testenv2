class TestenvError(Exception):
    """Base exception class"""


class BadConfiguration(TestenvError):
    pass


class RequestParserError(TestenvError):
    pass


class DeserializationError(TestenvError):

    def __init__(self, initial_data, details):
        super(DeserializationError, self).__init__()
        self.initial_data = initial_data
        self.details = details


class ValidationError(TestenvError):
    """Base validation error class"""

    def __init__(self, details):
        super(ValidationError, self).__init__()
        self.details = details


class XMLFormatValidationError(ValidationError):
    pass


class SPIDValidationError(ValidationError):
    pass


class XMLSchemaValidationError(ValidationError):
    pass


class GroupValidationError(ValidationError):
    pass


class StopValidation(TestenvError):
    pass


class SignatureVerificationError(TestenvError):
    pass


class UnknownEntityIDError(TestenvError):
    pass


class MetadataNotFoundError(TestenvError):

    def __init__(self, entity_id):
        self.entity_id = entity_id


class MetadataLoadError(TestenvError):
    pass


class NoCertificateError(TestenvError):
    pass


class ExpiredCertificateError(TestenvError):
    pass
