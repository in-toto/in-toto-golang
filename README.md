# Go in-toto verification
[![Build Status](https://travis-ci.com/in-toto/in-toto-golang.svg?branch=master)](https://travis-ci.com/in-toto/in-toto-golang)

Basic Go implementation of in-toto supply chain verification, based on the
[in-toto Python reference implementation](https://github.com/in-toto/in-toto).


## Basic usage of `InTotoVerify`
```go
package main

import (
  "fmt"
  "github.com/in-toto/in-toto-golang/in_toto"
)


func main() {
  layoutPath := "path/to/root.layout"
  pubKeyPath := "path/to/layout/signature/verification/public/key"
  linkDir := "path/to/dir/with/link/metadata/"


  // Load an RSA public key in PEM format used to verify the layout signature
  var pubKey in_toto.Key
  if err := pubKey.LoadPublicKey(pubKeyPath); err != nil {
    panic(err)
  }

  // Add public key to a key map, where the key id is used as map key
  // Add additional keys if the layout has multiple signatures
  var layouKeys = map[string]in_toto.Key{
    pubKey.KeyId: pubKey,
  }

  // Run all in-toto verification routines
  if err := in_toto.InTotoVerify(layoutPath, layouKeys, linkDir); err != nil {
    fmt.Println("Verification failed: ", err)
  } else {
    fmt.Println("Verification passed")
  }
}
```


## Not (yet) supported
* Sublayout verification
* Artifact rules of type `CREATE`, `DELETE` or `MODIFY`
* Signature schemes, other than `rsassa-pss-sha256`
* GPG keys
* Layout parameter substitution
* in-toto-run functionality
  *Note: A basic `runlib` does exist, however it is only used to execute the
  inspection commands in a layout and create the corresponding metadata. It
  cannot be used to create signed evidence (link metadata) for steps in a
  layout.*
* Hashing algorithms, other than `sha256` (in artifact recording)
* Symbolic links (in artifact recording)
* Exclude patterns (in artifact recording)
* Non-\*nix systems *(probably)*