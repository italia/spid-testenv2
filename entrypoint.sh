#!/bin/bash
set -eu

KEY_FILE=conf/idp.key
CRT_FILE=conf/idp.crt

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

exec "$@"
