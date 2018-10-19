package intoto

import (
  "os"
  "testing"
  )

func TestInTotoVerifyPass(t *testing.T) {
  layoutPath := "../test/data/demo.layout.template"
  pubKeyPath := "../test/data/alice.pub"
  linkDir := "../test/data"

  var pubKey Key
  if err := pubKey.LoadPublicKey(pubKeyPath); err != nil {
    t.Error(err)
  }

  var layouKeys = map[string]Key{
    pubKey.KeyId: pubKey,
  }

  // No error should occur
  if err := InTotoVerify(layoutPath, layouKeys, linkDir); err != nil {
    t.Error(err)
  }
}


func TestInTotoVerifyLayoutDoesNotExist(t *testing.T) {
  err := InTotoVerify("layout/does/not/exist", map[string]Key{},
      "link/dir/does/not/matter")
  // Asssert error type to PathError
  if _, ok := err.(*os.PathError); ok == false {
    t.Fail()
  }
}
