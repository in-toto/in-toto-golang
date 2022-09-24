#!/bin/sh

mkdir -p /tmp/spire/sockets
docker-compose -f ./test-infra/docker-compose.yaml up -d spire-server
sleep 5  # spire-server needs to be fully initialized before spire-agent comes up
docker-compose -f ./test-infra/docker-compose.yaml up -d spire-agent
sleep 5  # ensures spire-agent is fully up before registration
sh ./test-infra/register.sh
sleep 5  # ensures package registration is completed before it is required
sh ./test-infra/show-bundle.sh
sleep 5  # ensures spire-agent and spire-server is fully up and 
