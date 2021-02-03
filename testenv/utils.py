import calendar
import io
import re
import time
from collections import namedtuple
from copy import copy
from datetime import datetime

import lxml.etree as etree
from lxml import objectify

from testenv import log
from testenv.settings import MULTIPLE_OCCURRENCES_TAGS, SPID_ERRORS

TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
TIME_FORMAT_WITH_FRAGMENT = re.compile(
    r'^(\d{4,4}-\d{2,2}-\d{2,2}T\d{2,2}:\d{2,2}:\d{2,2})(\.\d*)?Z?$')

logger = log.logger


def get_spid_error(code):
    error_type = SPID_ERRORS.get(code)
    return error_type, 'ErrorCode nr{}'.format(code)


def check_utc_date(date):
    try:
        str_to_struct_time(date)
    except Exception:
        return False
    return True


def check_url(url):
    regex = re.compile(r'^https?://(\w+\.)*\w+\.\w+(:\d+)*$')
    is_matching = True if re.match(regex, url) else False
    return is_matching


check_utc_date.error_msg = 'la data non è in formato UTC'
check_url.error_msg = 'la url non è in formato corretto'


def str_to_datetime(val):
    nanoseconds_fmt = '%Y-%m-%dT%H:%M:%S.%fZ'
    seconds_fmt = '%Y-%m-%dT%H:%M:%SZ'
    for fmt in (nanoseconds_fmt, seconds_fmt):
        try:
            return datetime.strptime(val, fmt)
        except ValueError:
            pass

    truncated_to_nanoseconds = '{}Z'.format(val[:26])
    try:
        return datetime.strptime(truncated_to_nanoseconds, nanoseconds_fmt)
    except ValueError:
        raise ValueError('Cannot parse date: {}'.format(val))


def str_to_struct_time(timestr, format=TIME_FORMAT):
    """
    :param timestr:
    :param format:
    :return: UTC time
    """
    if not timestr:
        return 0
    try:
        then = time.strptime(timestr, format)
    except ValueError:  # assume it's a format problem
        try:
            elem = TIME_FORMAT_WITH_FRAGMENT.match(timestr)
        except Exception:
            raise
        then = time.strptime(elem.groups()[0] + 'Z', TIME_FORMAT)

    return time.gmtime(calendar.timegm(then))


def prettify_xml(msg):
    msg = etree.tostring(
        msg,
        pretty_print=True,
    )
    return msg.decode('utf-8')


def saml_to_dict(xmlstr):
    _err_msg = 'SP Metadata Parse Error'
    _xmlstr_preview_trunc = 254

    # sometimes a bytes objects, sometimes a '_io.TextIOWrapper' object ...
    if isinstance(xmlstr, io.TextIOWrapper):
        xmlstr_copy = xmlstr.read()
        xmlstr.seek(0)
    else:
        xmlstr_copy = copy(xmlstr)

    try:
        root = objectify.fromstring(xmlstr)
    except ValueError:
        logger.error(f'{_err_msg} [ValuerError] on: '
                     f'{xmlstr_copy[0:_xmlstr_preview_trunc]}')
        return {}
    # that's for resiliency ...
    except Exception:
        logger.error(f'{_err_msg} [Unknown Error] on: '
                     f'{xmlstr_copy[0:_xmlstr_preview_trunc]}')
        return {}

    def _obj(elem):
        children = {}
        for child in elem.iterchildren():
            subdict = _obj(child)

            if child.tag in MULTIPLE_OCCURRENCES_TAGS:
                existing = children.get(child.tag, None)
                if isinstance(existing, list):
                    existing.append(subdict)
                else:
                    children[child.tag] = [subdict]
            else:
                children[child.tag] = subdict

        text = elem.text
        if text is not None:
            text = text.strip()

        return {
            'attrs': dict(elem.attrib),
            'children': children,
            'text': text,
        }

    return {
        root.tag: _obj(root)
    }


def get_today_utc_date():
    now = datetime.utcnow()
    return now


Org = namedtuple('Org', ['name', 'url'])
Key = namedtuple('Key', ['use', 'value'])
Sso = namedtuple('SingleSignOn', ['binding', 'location'])
Slo = namedtuple('SingleLogout', ['binding', 'location'])
Atcs = namedtuple('AttributeConsumingService', ['service_name', 'attributes'])
Acs = namedtuple('AssertionConsumerService', ['location'])
