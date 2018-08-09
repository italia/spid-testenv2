# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class BadConfiguration(Exception):
    pass


class SpidValidationError(Exception):
    def __init__(self, xml, validation_errors):
        self.xml = xml
        self.validation_errors = validation_errors
