# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
from datetime import datetime

import lxml.etree as etree
import yaml

from saml2 import time_util
from testenv.settings import SPID_ERRORS


def get_config(f_name, f_type='yaml'):
    """
    Read server configuration from a json file
    """
    with open(f_name, 'r') as fp:
        if f_type == 'yaml':
            return yaml.load(fp)
        elif f_type == 'json':
            return json.loads(fp.read())


def get_spid_error(code):
    error_type = SPID_ERRORS.get(code)
    return error_type, 'ErrorCode nr{}'.format(code)


def check_utc_date(date):
    try:
        time_util.str_to_time(date)
    except Exception:
        return False
    return True


check_utc_date.error_msg = 'la data non è in formato UTC'


def str_to_time(val):
    try:
        return datetime.strptime(val, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        try:
            return datetime.strptime(val, '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            pass


def prettify_xml(msg):
    msg = etree.tostring(
        etree.XML(msg.encode('utf-8')),
        pretty_print=True,
        encoding='utf-8'
    )
    return msg.decode('utf-8')
