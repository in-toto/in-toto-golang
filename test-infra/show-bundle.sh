#!/bin/bash

docker exec test-infra_spire-server_1 \
/opt/spire/bin/spire-server bundle show \
-socketPath /run/spire/sockets/spire-registration.sock \