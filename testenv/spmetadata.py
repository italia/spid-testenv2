# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

import requests

from testenv import config
from testenv.exceptions import DeserializationError, MetadataLoadError, MetadataNotFoundError, ValidationError
from testenv.saml import (
    AssertionConsumerService, AttributeConsumingService, EntityDescriptor, KeyDescriptor, KeyInfo, RequestedAttribute,
    SingleLogoutService, SPSSODescriptor, X509Certificate, X509Data,
)
from testenv.utils import saml_to_dict
from testenv.validators import ServiceProviderMetadataXMLSchemaValidator, ValidatorGroup, XMLMetadataFormatValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ENTITYDESCRIPTOR = EntityDescriptor.tag()
SPSSODESCRIPTOR = SPSSODescriptor.tag()
KEYDESCRIPTOR = KeyDescriptor.tag()
KEYINFO = KeyInfo.tag()
X509DATA = X509Data.tag()
X509CERTIFICATE = X509Certificate.tag()
ASSERTION_CONSUMER_SERVICE = AssertionConsumerService.tag()
ATTRIBUTE_CONSUMING_SERVICE = AttributeConsumingService.tag()
REQUESTEDATTRIBUTE = RequestedAttribute.tag()
SINGLE_LOGOUT_SERVICE = SingleLogoutService.tag()


class ServiceProviderMetadataBaseLoader(object):

    def __init__(self, conf, validator):
        self._config = conf
        self._validator = validator

    def load(self):
        metadata = self._load()
        self._validate(metadata)
        return metadata

    def _validate(self, metadata):
        try:
            self._validator.validate(metadata)
        except ValidationError as e:
            raise DeserializationError(metadata, e.details)


class ServiceProviderMetadataFileLoader(ServiceProviderMetadataBaseLoader):

    def _load(self):
        try:
            return self._read_file_text()
        except Exception as e:
            raise MetadataLoadError(
                "Impossibile leggere il file '{}': '{}'"
                .format(self._config, e)
            )

    def _read_file_text(self):
        path = self._config
        with open(path, 'rb') as fp:
            return fp.read()


class ServiceProviderMetadataHTTPLoader(ServiceProviderMetadataBaseLoader):

    def _load(self):
        try:
            return self._make_request()
        except Exception as e:
            raise MetadataLoadError(
                "La richiesta all'endpoint HTTP '{}' è fallita: '{}'"
                .format(self._config.get('url'), e)
            )

    def _make_request(self):
        response = requests.get(self._config.get('url'))
        response.raise_for_status()
        return response.content


class ServiceProviderMetadata(object):

    def __init__(self, loader):
        self._loader = loader

    @property
    def root_tag(self):
        return ENTITYDESCRIPTOR

    @property
    def root(self):
        return self._metadata.get(
            self.root_tag, {}
        )

    @property
    def entity_id(self):
        return self.root.get(
            'attrs', {}
        ).get('entityID', None)

    def certs(self, use='signing'):
        key_descriptors = self.root.get(
            'children', {}
        ).get(SPSSODESCRIPTOR, {}
              ).get(
            'children', {}
        ).get(
            KEYDESCRIPTOR, []
        )
        _certs = []
        for key_descriptor in key_descriptors:
            _key_descriptor = key_descriptor.get(
                'children', {}
            )
            if key_descriptor.get('attrs', {}
                                  ).get('use') == use:
                _cert = _key_descriptor.get(
                    KEYINFO, {}
                ).get(
                    'children', {}
                ).get(
                    X509DATA, {}
                ).get(
                    'children', {}
                ).get(
                    X509CERTIFICATE, {}
                ).get('text', None)
                if _cert is not None:
                    splitted_cert = _cert.split('\n')
                    _cert = ''.join([s.strip() for s in splitted_cert])
                    _certs.append(_cert)
        return _certs

    @property
    def assertion_consumer_services(self):
        acss = self.root.get(
            'children', {}
        ).get(SPSSODESCRIPTOR, {}
              ).get(
            'children', {}
        ).get(
            ASSERTION_CONSUMER_SERVICE, []
        )
        return [
            acs.get('attrs', {}) for acs in acss
        ]

    def assertion_consumer_service(self, binding=None, index=None):
        return [
            acs for acs in self.assertion_consumer_services if (
                binding is not None and acs.get('Binding') == binding
            ) or (
                index is not None and acs.get('index') == index
            )
        ]

    @property
    def attribute_consuming_services(self):
        return self.root.get(
            'children', {}
        ).get(SPSSODESCRIPTOR, {}
              ).get(
            'children', {}
        ).get(
            ATTRIBUTE_CONSUMING_SERVICE, []
        )

    def attribute_consuming_service(self, index='0'):
        return [
            atcs for atcs in self.attribute_consuming_services if atcs.get(
                'attrs', {}
            ).get('index') == index
        ]

    def attributes(self, index='0'):
        services = self.attribute_consuming_service(index)
        result_attributes = {
            'required': [],
            'optional': []
        }
        if services:
            service = services[0]
            requested_attributes = service.get(
                'children', {}
            ).get(REQUESTEDATTRIBUTE, []
                  )
            for requested_attribute in requested_attributes:
                _attrs = requested_attribute.get(
                    'attrs', {}
                )
                is_required = _attrs.get('isRequired', None)
                name = _attrs.get('Name')
                if is_required and is_required == 'true':
                    result_attributes['required'].append(name)
                else:
                    result_attributes['optional'].append(name)
        return result_attributes

    @property
    def single_logout_services(self):
        slos = self.root.get(
            'children', {}
        ).get(SPSSODESCRIPTOR, {}
              ).get(
            'children', {}
        ).get(
            SINGLE_LOGOUT_SERVICE, []
        )
        return [
            slo.get('attrs', {}) for slo in slos
        ]

    def single_logout_service(self, binding):
        return [
            slo for slo in self.single_logout_services if slo.get('Binding') == binding
        ]

    @property
    def _metadata(self):
        metadata = self._loader.load()
        return saml_to_dict(metadata)


class ServiceProviderMetadataRegistry(object):

    def __init__(self):
        self._metadata = {}

    def register(self, metadata):
        try:
            self._register(metadata)
        except MetadataLoadError as e:
            logger.error(
                "Impossibile aggiungere metadata al registry: '{}'".format(e))

    def _register(self, metadata):
        entity_id = metadata.entity_id
        self._metadata[entity_id] = metadata

    def get(self, entity_id):
        try:
            return self._metadata[entity_id]
        except KeyError:
            raise MetadataNotFoundError(entity_id)

    @property
    def service_providers(self):
        return list(self._metadata.keys())


registry = None


def build_metadata_registry():
    global registry
    registry = ServiceProviderMetadataRegistry()
    _populate_registry(registry)


def _populate_registry(registry):
    for source_type, source_params in config.params.metadata.items():
        for param in source_params:
            loader = _get_loader(source_type, param)
            metadata = ServiceProviderMetadata(loader)
            registry.register(metadata)


def _get_loader(source_type, source_params):
    Loader = {
        'local': ServiceProviderMetadataFileLoader,
        'remote': ServiceProviderMetadataHTTPLoader,
    }[source_type]
    validator = ValidatorGroup(
        [XMLMetadataFormatValidator(), ServiceProviderMetadataXMLSchemaValidator()])
    return Loader(source_params, validator)
