package main

import (
  "testing"
  )

func TestInTotoVerify(t *testing.T) {
  layoutPath := "../test/data/demo.layout.template"
  pubKeyPath := "../test/data/alice.pub"
  linkDir := "../test/data"

  var pubKey Key
  pubKey.LoadPublicKey(pubKeyPath)

  var layouKeys = map[string]Key{
    pubKey.KeyId: pubKey,
  }

  InTotoVerify(layoutPath, layouKeys, linkDir)

}