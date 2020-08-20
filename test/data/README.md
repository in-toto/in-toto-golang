# Test Data

## How to generate the test data

We load keys from disk only in PKCS8, PKCS1 or PKCX format.
The next sections describe, how you can generate such keys via openssl.
Currently only keys **without password protection** are supported.

### RSA

TODO: write description for RSA key generation

### ECDSA

First you need to generate an ecdsa key in traditional ec key format via:

`$ openssl ecparam -name secp521r1 -genkey -noout -out <filename>.ec`

Then you can transform this key into PKCS8 format via:

`$ openssl pkcs8 -topk8 -nocrypt -in <filename>.ec -out <filename>`

Next generate the public key via:

`$ openssl ec -in <filename> -pubout -out <filename>.pub`


### ED25519

Private key:

`$ openssl genpkey -algorithm ed25519 -outform PEM -out <filename>`

Public key:

`$ openssl pkey -in <filename>  -pubout > <filename>.pub`

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
