# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import os
import os.path

from flask import Flask

from saml2.cert import OpenSSLWrapper
from testenv.exceptions import BadConfiguration
from testenv.server import IdpServer
from testenv.utils import get_config


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

    args = parser.parse_args()
    # Init server
    config = get_config(args.config, args.configuration_type)

    if args.dummy_cert:
        if not os.path.exists('.tmpdir'):
            os.mkdir('.tmpdir')
        openssl = OpenSSLWrapper()
        config['cert_file'], config['key_file'] = openssl.create_certificate(
            {
                "cn": "localhost",
                "country_code": "IT",
                "state": "Lazio",
                "city": "Roma",
                "organization":
                "MyCompany",
                "organization_unit": "IDP"
            },
            request=False,
            write_to_file=True,
            key_length=2048,
            cert_dir=".tmpdir"
        )

    try:
        os.environ['FLASK_ENV'] = 'development'
        server = IdpServer(
            app=Flask(__name__, static_url_path='/static'), config=config
        )
        # Start server
        server.start()
    except BadConfiguration as e:
        print(e)
