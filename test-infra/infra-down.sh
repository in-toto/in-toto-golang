#!/bin/sh

docker-compose -f ./test-infra/docker-compose.yaml down
docker rmi intoto-run:latest
rm -rf /tmp/spire
