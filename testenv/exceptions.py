# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class TestenvError(Exception):
    """Base exception class"""


class BadConfiguration(TestenvError):
    pass


class RequestParserError(TestenvError):
    pass
