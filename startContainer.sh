#!/bin/sh

NAME="test_spid_ip"

ExistingContainer="$(docker ps --filter name="$NAME" -q -a)"

if [[ ! -z "$ExistingContainer" ]]; then
    RunningCointainer="$(docker ps --filter name="$NAME" -q)"
    if [[ ! -z "$RunningCointainer" ]]; then
        docker kill "$RunningCointainer"
    fi
    docker start "$NAME"
else
    docker run --name "$NAME" -d -p 8088:8088 -v $(pwd)/conf:/app/conf italia/spid-testenv2
fi
