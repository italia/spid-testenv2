# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
from logging.handlers import RotatingFileHandler

global logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

handler = RotatingFileHandler(
    'spid.log', maxBytes=500000, backupCount=1
)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(module)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
