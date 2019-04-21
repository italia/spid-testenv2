# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
from copy import deepcopy

import yaml
from voluptuous import ALLOW_EXTRA, All, Any, In, Invalid, Length, Required, Schema, Url

from testenv import settings
from testenv.exceptions import BadConfiguration


class ConfigValidator(object):

    def __init__(self, confdata):
        self._confdata = confdata
        self._init_schema()
        self._init_custom_validators()

    def _init_schema(self):
        self._schema = {
            Required('key_file'): str,
            Required('cert_file'): str,
            Required('base_url'): Url(),
            'host': str,
            'port': Any(int, str),
            'debug': bool,
            'https': bool,
            'https_cert_file': str,
            'https_key_file': str,
            'users_file': str,
            'behind_reverse_proxy': bool,
            'can_add_user': bool,
            'storage': All(str, In(['file', 'postgres'])),
            'db_url': str,
            'endpoints': {
                'single_logout_service': str,
                'single_sign_on_service': str,
            },
            'metadata': {
                'local': All([str], Length(min=0)),
                'remote': All(
                    [
                        {
                            Required('url'): Url(),
                            'cert': str,
                        }
                    ],
                    Length(min=0),
                )
            }
        }

    def _init_custom_validators(self):
        def check_https(data):
            https = data.get('https')
            key_path = data.get('https_key_file')
            cert_path = data.get('https_cert_file')
            if https and not all([key_path, cert_path]):
                raise Invalid(
                    'Errore modalità HTTPS: chiave e/o certificato assenti')
            return data

        def check_endpoints(data):
            for endpoint in data.get('endpoints', {}).values():
                if not endpoint.startswith('/'):
                    raise Invalid(
                        'Errore nella configurazione delle URL: '
                        'i path devono essere relativi ed iniziare '
                        'con "/" (slash) - URL {}'.format(endpoint)
                    )
            return data

        self._custom_validators = [
            check_https,
            check_endpoints,
        ]

    def validate(self):
        try:
            self._validate()
        except Invalid as e:
            self._fail(e)

    @staticmethod
    def _fail(exc):
        raise BadConfiguration(str(exc))

    def _validate(self):
        schema = Schema(
            All(self._schema, *self._custom_validators),
            extra=ALLOW_EXTRA,
        )
        schema(self._confdata)


class Config(object):

    def __init__(self, confdata):
        self._confdata = confdata
        self._idp_key = self._load_idp_key()
        self._idp_certificate = self._load_idp_certificate()

    def _load_idp_key(self):
        try:
            return self._read_file_bytes(self.idp_key_file_path)
        except Exception:
            self._fail('Impossibile ottenere la chiave privata dal file {}'.format(
                self.key_file_path))

    @staticmethod
    def _read_file_bytes(path):
        with open(path, 'rb') as fp:
            return fp.read()

    @property
    def idp_key_file_path(self):
        return self._confdata['key_file']

    @staticmethod
    def _fail(message):
        raise BadConfiguration(message)

    def _load_idp_certificate(self):
        try:
            return self._read_file_bytes(self.idp_certificate_file_path)
        except Exception:
            self._fail('Impossibile ottenere il certificato dal file {}'.format(
                self.cert_file_path))

    @property
    def idp_certificate_file_path(self):
        return self._confdata['cert_file']

    @property
    def idp_key(self):
        return self._idp_key

    @property
    def idp_certificate(self):
        return self._idp_certificate

    @property
    def entity_id(self):
        return self._confdata['base_url']

    @property
    def host(self):
        return self._confdata.get('host', '0.0.0.0')

    @property
    def port(self):
        return self._confdata.get('port', 8000)

    @property
    def debug(self):
        return self._confdata.get('debug', True)

    @property
    def https(self):
        return self._confdata.get('https', False)

    @property
    def https_key_file_path(self):
        return self._confdata.get('https_key_file')

    @property
    def https_certificate_file_path(self):
        return self._confdata.get('https_cert_file')

    @property
    def can_add_user(self):
        return self._confdata.get('can_add_user', True)

    @property
    def database_admin_interface(self):
        return self._confdata.get('database_admin_interface', False)

    @property
    def show_response_options(self):
        return self._confdata.get('show_response_options', True)

    @property
    def endpoints(self):
        return {
            ep: self._confdata.get('endpoints', {}).get(ep)
            for ep in ('single_sign_on_service', 'single_logout_service')
        }

    @property
    def absolute_sso_url(self):
        return self.entity_id + self.endpoints.get('single_sign_on_service')

    @property
    def absolute_slo_url(self):
        return self.entity_id + self.endpoints.get('single_logout_service')

    @property
    def metadata(self):
        return deepcopy(self._confdata.get('metadata', {}))

    @property
    def users_file_path(self):
        return self._confdata.get('users_file', 'conf/users.json')

    @property
    def users_db(self):
        return self._confdata.get('users_db', None)

    @property
    def pysaml2compat(self):
        # FIXME remove after pysaml2 drop
        return {
            'entityid': self.entity_id,
            'description': 'SPID Test IdP',
            'service': {
                'idp': {
                    'name': 'SPID Testenv',
                    'endpoints': {
                        'single_sign_on_service': [
                            ('{}{}'.format(self.entity_id, self.endpoints.get('single_sign_on_service') or ''),
                             settings.BINDING_HTTP_REDIRECT),
                            ('{}{}'.format(self.entity_id, self.endpoints.get('single_sign_on_service') or ''),
                             settings.BINDING_HTTP_POST),
                        ],
                        'single_logout_service': [
                            ('{}{}'.format(self.entity_id, self.endpoints.get('single_logout_service') or ''),
                             settings.BINDING_HTTP_REDIRECT),
                            ('{}{}'.format(self.entity_id, self.endpoints.get('single_logout_service') or ''),
                             settings.BINDING_HTTP_POST),
                        ],
                    },
                    'policy': {
                        'default': {
                            'name_form': settings.NAME_FORMAT_BASIC,
                        },
                    },
                    'name_id_format': [
                        settings.NAMEID_FORMAT_TRANSIENT,
                    ]
                },
            },
            'debug': 1,
            'key_file': self.idp_key_file_path,
            'cert_file': self.idp_certificate_file_path,
            'metadata': self.metadata,
            'logger': {
                'rotating': {
                    'filename': 'idp.log',
                    'maxBytes': 500000,
                    'backupCount': 1,
                },
                'loglevel': 'debug',
            }
        }

    @property
    def behind_reverse_proxy(self):
        return self._confdata.get('behind_reverse_proxy', False)

    def receivers(self, service):
        entity_id = self.entity_id.rstrip('/')
        endpoint = self.endpoints[service].lstrip('/')
        return ['{}/{}'.format(entity_id, endpoint)]


class BaseConfigParser(object):

    def __init__(self, path):
        self._path = path
        self._fp = None

    def parse(self):
        try:
            return self._parse()
        except OSError:
            raise BadConfiguration(
                'Impossibile accedere al file di configurazione: {}'.format(self._path))
        except Exception:
            raise BadConfiguration(
                'Errore di sintassi nel file di configurazione: {}'.format(self._path))

    def _parse(self):
        with open(self._path, 'r') as fp:
            self._fp = fp
            return self._deserialize()


class YAMLConfigParser(BaseConfigParser):

    def _deserialize(self):
        return yaml.load(self._fp)


class JSONConfigParser(BaseConfigParser):

    def _deserialize(self):
        return json.load(self._fp.read())


def _get_parser_class(fileformat):
    return {
        'yaml': YAMLConfigParser,
        'json': JSONConfigParser,
    }[fileformat]


params = None


def load(f_name, f_type='yaml'):
    """
    Load configuration from a YAML or JSON file
    """
    global params
    parser = _get_parser_class(f_type)(f_name)
    confdata = parser.parse()
    ConfigValidator(confdata).validate()
    params = Config(confdata)
