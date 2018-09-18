# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import os
import os.path

from flask import Flask

from testenv import config, spmetadata
from testenv.exceptions import BadConfiguration
from testenv.server import IdpServer

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
    args = parser.parse_args()
    try:
        config.load(args.config, args.configuration_type)
    except BadConfiguration as e:
        print(e)
    else:
        spmetadata.build_metadata_registry()
        os.environ['FLASK_ENV'] = 'development'
        server = IdpServer(app=Flask(__name__, static_url_path='/static'))
        server.start()
