#!/bin/bash
set -eu

KEY_FILE=conf/idp.key
CRT_FILE=conf/idp.crt

CONFIG_YAML=conf/config.yaml
SP_METADATA=conf/sp_metadata.xml

EXAMPLES_DIR=/usr/local/share/spid-testenv2/

if [ ! -e $KEY_FILE ] && [ ! -e $CRT_FILE ]; then
    echo "Generating $KEY_FILE and $CRT_FILE..."
    openssl req -x509 \
                -nodes \
                -sha256 \
                -subj '/C=IT' \
                -newkey rsa:2048 \
                -keyout $KEY_FILE \
                -out $CRT_FILE
fi

if [ ! -e $CONFIG_YAML ]; then
    echo "Using default $CONFIG_YAML..."
    cp $EXAMPLES_DIR/config.yaml.example $CONFIG_YAML
fi

if [ ! -e $SP_METADATA ]; then
    echo "Using default $SP_METADATA..."
    cp $EXAMPLES_DIR/sp_metadata.xml.example $SP_METADATA
fi

exec "$@"
