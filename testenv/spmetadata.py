from glob import glob
from itertools import chain

import requests
from lxml.etree import LxmlError

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


class ServiceProviderMetadataRegistry:
    def __init__(self):
        self._validators = ValidatorGroup([
            XMLMetadataFormatValidator(),
            ServiceProviderMetadataXMLSchemaValidator(),
            SpidMetadataValidator(),
        ])
        self._index_metadata()

    def load(self, entity_id):
        """
        Loads the metadata of a Service Provider.

        Args:
            entity_id (str): Entity id of the SP (usually a URL or a URN).

        Returns:
            A ServiceProviderMetadata instance.

        Raises
            MetadataNotFoundError: If there is no metadata associated to
                the entity id.
            DeserializationError: If the metadata associated to the entity id
                is not valid.
        """
        entity_id = entity_id.strip()

        fresh_metadata = None

        metadata = self._metadata.get(entity_id, None)
        if not metadata:
            # Try to reload all sources to see if the unknown entity id was added there
            # somewhere.
            logger.debug(
                "Unknown entityId '{}`, reloading all the sources.".format(entity_id)
            )
            self._index_metadata()
        else:
            # We got an known entity id, try to load its metadata the previously known
            # location.
            try:
                fresh_metadata = metadata.loader.load(metadata.location)
                if fresh_metadata.entity_id != entity_id:
                    raise MetadataLoadError
            except MetadataLoadError as e:
                logger.debug(
                    ("{}\n"
                     "Cannot find entityId '{}` at its previous location '{}`"
                     "reloading all the sources").format(e, entity_id, metadata.location)
                )
                self._index_metadata()

        if not fresh_metadata:
            try:
                metadata = self._metadata[entity_id]
                fresh_metadata = metadata.loader.load(metadata.location)
            except (KeyError, MetadataLoadError):
                raise MetadataNotFoundError(entity_id)

            if metadata.entity_id != entity_id:
                raise MetadataNotFoundError(entity_id)
        try:
            self._validators.validate(fresh_metadata.xml)
        except ValidationError as e:
            raise DeserializationError(fresh_metadata.xml, e.details)

        return fresh_metadata

    def load_all(self):
        """
        Returns a dict containing all ServerProviderMetadata loaded,
        indexed by entityId.
        """
        self._index_metadata()

        return self._metadata

    def _index_metadata(self):
        """
        Populate self._metadata with the up to date information from all the
        configured SP metadata.
        """

        # dict of { entity_id: ServiceProviderMetadata }
        self._metadata = {}

        # Possible sources of metadata, ordered by preference
        # (ie. the first source will be preferred in case of duplicate
        # entity ids).
        SOURCE_TYPES = ['local', 'db', 'remote']

        for source_type in reversed(SOURCE_TYPES):
            if source_type not in config.params.metadata:
                continue

            source_params = config.params.metadata[source_type]

            loader = {
                'local': ServiceProviderMetadataFileLoader,
                'remote': ServiceProviderMetadataHTTPLoader,
                'db': ServiceProviderMetadataDbLoader,
            }[source_type](source_params)

            metadata = loader.load_all()
            for dup in set(metadata.keys()).intersection(set(self._metadata)):
                logger.info(
                    "Discarding duplicate entity_id `{}' from '{}`.".format(
                        dup,
                        self._metadata[dup].location
                    )
                )

            self._metadata.update(metadata)


registry = None


def build_metadata_registry():
    global registry
    registry = ServiceProviderMetadataRegistry()


class LoadAllMixin(object):
    def load_all(self):
        """
        Loads all the available SP metadata, skipping duplicates.

        Returns:
            A dict containing all local ServerProviderMetadata loaded,
            indexed by entityId.
        """
        metadata = None
        ret = {}

        for location in self._locations:
            try:
                metadata = self.load(location)
            except MetadataLoadError as e:
                logger.info(
                    "Skipping '{}` because of a load error: {}".format(location, e)
                )
                continue

            if metadata.entity_id in ret:
                logger.info(
                    "Discarding duplicate entity_id `{}' from '{}`.".format(
                        metadata.entity_id,
                        metadata.location
                    )
                )
                continue

            ret[metadata.entity_id] = metadata

        return ret


class ServiceProviderMetadataFileLoader(LoadAllMixin, object):
    """
    Loads SP metadata from a list of files.

    Args:
        locations (list of str): List of paths to load. Paths can also contain
            globbing metacharacters.
    """

    def __init__(self, locations):
        files = [glob(entry) for entry in locations]

        self._locations = list(chain.from_iterable(files))

    def load(self, location):
        """
        Loads the SP metadata from file.

        Args:
            location (str): The path of file.

        Returns:
            A ServiceProviderMetadata instance.

        Raises:
            MetadataLoadError: If the load fails.
        """
        try:
            with open(location, 'rb') as fp:
                metadata = ServiceProviderMetadata(fp.read(), self, location)
        except (IOError, LxmlError) as e:
            raise MetadataLoadError(
                "Failed to load '{}': '{}'".format(location, e)
            )
        logger.debug(
            "Loaded metadata for '{}` from '{}`".format(
                metadata.entity_id,
                location
            )
        )
        return metadata


class ServiceProviderMetadataHTTPLoader(LoadAllMixin, object):
    """
    Loads SP metadata from a list of HTTP URLs.

    Args:
        urls (list of str): List of HTTP URLs to load.
    """

    def __init__(self, locations):
        self._locations = locations

    def load(self, location):
        """
        Loads the SP metadata from HTTP.

        Args:
            location (str): The URL of the metadata to load.

        Returns:
            A ServiceProviderMetadata instance.

        Raises:
            MetadataLoadError: If the load fails.
        """

        try:
            response = requests.get(location)
            response.raise_for_status()
            metadata = ServiceProviderMetadata(response.content, self, location)
        except Exception as e:
            raise MetadataLoadError(
                "Request to HTTP endpoint '{}': '{}'".format(location, e)
            )

        logger.debug(
            "Loaded metadata for '{}` from '{}`".format(
                metadata.entity_id,
                location
            )
        )

        return metadata


class ServiceProviderMetadataDbLoader:
    """Loads metadata from the configured database"""

    def __init__(self, conf):
        self._provider = DatabaseSPProvider(conf)

    def load(self, entity_id):
        metadata = self._provider.get(entity_id)
        if metadata is None:
            raise MetadataNotFoundError(entity_id)
        return ServiceProviderMetadata(metadata, self, 'db')

    def load_all(self):
        """
        Returns a dict containing all 'db' ServerProviderMetadata loaded,
        indexed by entityId."""
        return {
            entity_id: ServiceProviderMetadata(xml, self, 'db')
            for (entity_id, xml) in self._provider.all().items()
        }


class ServiceProviderMetadata(object):
    """
    Object representing the metadata of a Service Provider.

    Args:
        xml (str): The metadata as XML.
        loader (instance of ServiceProviderMetadata{File,HTTP,Db}Loader): The loader the
            metadata was loaded with.
        location (str): The source the metadata was loaded from.
            It's a path for 'local' metadata, a URL for 'remote' and
            the string 'db' for 'db'.
    """
    def __init__(self, xml, loader, location):
        self.xml = xml
        self.loader = loader
        self.location = location
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
