# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from glob import glob
from itertools import chain

import requests

from testenv import config, log
from testenv.exceptions import DeserializationError, MetadataLoadError, MetadataNotFoundError, ValidationError
from testenv.saml import (
    AssertionConsumerService, AttributeConsumingService, EntityDescriptor, KeyDescriptor, KeyInfo, RequestedAttribute,
    SingleLogoutService, SPSSODescriptor, X509Certificate, X509Data,
)
from testenv.storages import DatabaseSPProvider
from testenv.utils import saml_to_dict
from testenv.validators import (
    ServiceProviderMetadataXMLSchemaValidator, SpidMetadataValidator, ValidatorGroup, XMLMetadataFormatValidator,
)

logger = log.logger

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


class ServiceProviderMetadataRegistry(object):
    def __init__(self):
        self._loaders = []
        for source_type, source_params in config.params.metadata.items():
            self._loaders.append({
                'local': ServiceProviderMetadataFileLoader,
                'remote': ServiceProviderMetadataHTTPLoader,
                'db': ServiceProviderMetadataDbLoader,
            }[source_type](source_params))
        self._validators = ValidatorGroup([
            XMLMetadataFormatValidator(),
            ServiceProviderMetadataXMLSchemaValidator(),
            SpidMetadataValidator(),
        ])

    def get(self, entity_id):
        entity_id = entity_id.strip()
        for loader in self._loaders:
            try:
                metadata = loader.get(entity_id)
                try:
                    self._validators.validate(metadata.xml)
                    return metadata
                except ValidationError as e:
                    raise DeserializationError(metadata.xml, e.details)
            except MetadataNotFoundError:
                continue

        raise MetadataNotFoundError(entity_id)

    def all(self):
        """Returns the list of entityIDs of all the known Service Providers"""
        return [i for l in self._loaders for i in l.all()]


registry = None


def build_metadata_registry():
    global registry
    registry = ServiceProviderMetadataRegistry()


class ServiceProviderMetadataFileLoader(object):
    """Loads metadata from the configured files

    This could be improved automatically reloading the metadata when
    file timestamps change
    """

    def __init__(self, conf):
        self._metadata = {}

        files = [glob(entry) for entry in conf]
        for file in list(chain.from_iterable(files)):
            try:
                with open(file, 'rb') as fp:
                    metadata = ServiceProviderMetadata(fp.read())
                    self._metadata[metadata.entity_id] = metadata
                    logger.debug("Loaded metadata for: " + metadata.entity_id)
            except Exception as e:
                raise MetadataLoadError(
                    "Impossibile leggere il file '{}': '{}'".format(file, e)
                )

    def get(self, entity_id):
        try:
            return self._metadata[entity_id]
        except KeyError:
            raise MetadataNotFoundError(entity_id)

    def all(self):
        return self._metadata.keys()


class ServiceProviderMetadataHTTPLoader(object):
    """Loads metadata from the configured URLs"""

    def __init__(self, conf):
        self._metadata = {}
        for url in conf:
            try:
                response = requests.get(url)
                response.raise_for_status()
                metadata = ServiceProviderMetadata(response.content)
                self._metadata[metadata.entity_id] = metadata
            except Exception as e:
                raise MetadataLoadError(
                    "La richiesta all'endpoint HTTP '{}': '{}'".format(url, e)
                )

    def get(self, entity_id):
        try:
            return self._metadata[entity_id]
        except KeyError:
            raise MetadataNotFoundError(entity_id)

    def all(self):
        return self._metadata.keys()


class ServiceProviderMetadataDbLoader(object):
    """Loads metadata from the configured database"""

    def __init__(self, conf):
        self._provider = DatabaseSPProvider(conf)

    def get(self, entity_id):
        metadata = self._provider.get(entity_id)
        if metadata is None:
            raise MetadataNotFoundError(entity_id)
        return ServiceProviderMetadata(metadata)

    def all(self):
        return self._provider.all().keys()


class ServiceProviderMetadata(object):

    def __init__(self, xml):
        self.xml = xml
        self._metadata = saml_to_dict(xml)

    @property
    def root(self):
        return self._metadata.get(
            self.root_tag, {}
        )

    @property
    def root_tag(self):
        return ENTITYDESCRIPTOR

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
