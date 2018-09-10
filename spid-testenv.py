# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import os
from os.path import join as pjoin, isfile
from socket import gethostname
from six.moves.urllib.request import urlopen

from flask import Flask
from saml2.cert import OpenSSLWrapper

from testenv.exceptions import BadConfiguration
from testenv.server import IdpServer
from testenv.utils import get_config


def create_cert(dpath, cn):
    openssl = OpenSSLWrapper()

    cert_info = {
        "country_code": "IT",
        "state": "Lazio",
        "city": "Roma",
        "organization": "MyCompany",
        "organization_unit": "IDP"
    }

    cert_path, key_path = pjoin(dpath, cn + ".crt"), pjoin(dpath, cn + ".key")
    ssl_context = cert_path, key_path

    if isfile(ssl_context[0]) and isfile(ssl_context[1]):
        return ssl_context

    return openssl.create_certificate(
        cert_info=dict(cn=cn, **cert_info),
        request=False,
        write_to_file=True,
        key_length=2048,
        cert_dir=dpath
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', dest='config', help='Path to configuration file.',
        default='./conf/config.yaml'
    )
    parser.add_argument(
        '-ct', dest='configuration_type',
        help='Configuration type [yaml|json]', default='yaml'
    )
    parser.add_argument(
        '--dummy-cert', dest='dummy_cert', action="store_true",
        help='Generate and use dummy self-signed certificate in .tmpdir/ and ignore the settings in config.yaml', default=False
    )
    parser.add_argument(
        '--insecure-add-sp', dest='insecure_sp', required=False,
        help='Provision a service provider from metadata url', default=False
    )

    args = parser.parse_args()
    # Init server
    config = get_config(args.config, args.configuration_type)

    # This dir contains temporary files for a quickstart.
    if not os.path.exists('.tmpdir'):
        os.mkdir('.tmpdir')

    if args.insecure_sp:
        metadata_path = pjoin(
            ".tmpdir", "_" + args.insecure_sp.replace("/", "_") + ".xml")
        with open(metadata_path, "wb") as fh:
            metadata = urlopen(args.insecure_sp).read()
            fh.write(metadata)
        if not config.get('metadata'):
            config['metadata'] = {'local': []}
        config['metadata']['local'].append(metadata_path)

    if args.dummy_cert:
        # With dummy certs I get ssl for free.
        host = gethostname() + ".local"
        config['https'] = True
        config[
            'base_url'] = 'https://{host}:{port}'.format(host=host, port=config['port'])
        config['cert_file'], config[
            'key_file'] = create_cert('.tmpdir', 'localhost')
        config['https_cert_file'], config[
            'https_key_file'] = create_cert('.tmpdir', host)

    try:
        os.environ['FLASK_ENV'] = 'development'
        server = IdpServer(
            app=Flask(__name__, static_url_path='/static'), config=config
        )
        # Start server
        server.start()
    except BadConfiguration as e:
        print(e)
