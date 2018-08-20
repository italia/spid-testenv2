# -*- coding: utf-8 -*-
from __future__ import unicode_literals


class FakeRequest(object):
    def __init__(self, data):
        self.saml_request = data
