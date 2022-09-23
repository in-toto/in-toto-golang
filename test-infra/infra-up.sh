#!/bin/sh

mkdir -p /tmp/spire/sockets
docker-compose -f ./test-infra/docker-compose.yaml up -d spire-server
sleep 5  # spire-server needs to be fully initialized before spire-agent comes up
docker-compose -f ./test-infra/docker-compose.yaml up -d spire-agent
sh ./test-infra/register.sh
sh ./test-infra/show-bundle.sh
