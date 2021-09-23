#!/bin/bash

docker exec test-infra_spire-server_1 \
/opt/spire/bin/spire-server bundle show \
-registrationUDSPath /run/spire/sockets/spire-registration.sock \