# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import argparse
import logging
import os
import os.path

from flask import Flask
from werkzeug.contrib.fixers import ProxyFix

from testenv import config, log, spmetadata
from testenv.exceptions import BadConfiguration, DeserializationError, ValidationError
from testenv.server import IdpServer

logging.basicConfig(level=logging.INFO)
logger = log.logger

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
        logger.error(e)
    else:
        try:
            spmetadata.build_metadata_registry()
        except (ValidationError, DeserializationError) as e:
            for err in e.details:
                logger.error(err)
        os.environ['FLASK_ENV'] = 'development'
        app = Flask(__name__, static_url_path='/static')
        if config.params.behind_reverse_proxy:
            app.wsgi_app = ProxyFix(app.wsgi_app)
        server = IdpServer(app=app)
        server.start()
