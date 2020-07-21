# Test Data

## Go Specifics

### ECDSA

The Go ecdsa library only supports FIPS 186-3.
The following curves are supported:

* secp521r1
* ...

The following curves are for example **not** supported:

* secp256k1
* ...

## Test Data Overview

| file | comment |
|------|---------|
| alice.pub | RSA public key |
| canonical-test.link | .. |
| carol | ed25519 key as PKCS8 |
| carol.pub | pub key of carol |
| carol-invalid | to be removed |
| dan | RSA private key |
| dan.pub | pub key of dan |
| erin | EC private Key (secp256k1) |
| erin.pub | EC public key of erin (secp256k1) |
| frank | EC private key PKCS8 (secp521r1) |
| frank.pub | EC public key of frank |
| foo.2f89b927.link | .. |
| foo.776a00e2.link | .. |
| foo.tar.gz | .. |
| package.2f89b927.link | .. |
| sub_layout.556caebd.link | .. |
| super.layout | .. |
| write-code.776a00e2.link | .. |
