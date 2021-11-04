#!/bin/bash

## DEMO REGISTRATIONS ##
#intoto-write-code
docker exec test-infra_spire-server_1 \
/opt/spire/bin/spire-server entry create \
-selector unix:uid:1000 \
-registrationUDSPath /run/spire/sockets/spire-registration.sock \
-spiffeID spiffe://example.com/write-code \
-parentID spiffe://example.com/spire/agent/sshpop/21Aic_muK032oJMhLfU1_CMNcGmfAnvESeuH5zyFw_g

#intoto-pakcage
docker exec test-infra_spire-server_1 \
/opt/spire/bin/spire-server entry create \
-selector unix:uid:1001 \
-registrationUDSPath /run/spire/sockets/spire-registration.sock \
-spiffeID spiffe://example.com/package \
-parentID spiffe://example.com/spire/agent/sshpop/21Aic_muK032oJMhLfU1_CMNcGmfAnvESeuH5zyFw_g

