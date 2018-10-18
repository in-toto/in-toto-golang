package main

import (
  "fmt"
  "encoding/pem"
  "encoding/hex"
  "io/ioutil"
  "crypto"
  "crypto/rsa"
  "crypto/x509"
  "crypto/sha256"
  "strings"
)


func VerifySignature(key Key, sig Signature, data []byte) {
  // Create rsa.PublicKey object from DER encoded public key string as
  // found in the public part of the keyval part of a securesystemslib key dict
  keyReader := strings.NewReader(key.KeyVal.Public)
  pemBytes, _ := ioutil.ReadAll(keyReader)

  block, _ := pem.Decode(pemBytes)
  if block == nil {
    panic("Failed to parse PEM block containing the public key")
  }

  pub, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil {
    panic("Failed to parse DER encoded public key: " + err.Error())
  }

  var rsaPub *rsa.PublicKey = pub.(*rsa.PublicKey)
  rsaPub, ok := pub.(*rsa.PublicKey)
  if !ok {
    panic("Invalid value returned from ParsePKIXPublicKey")
  }

  hashed := sha256.Sum256(data)

  // Create hex bytes from the signature hex string
  sigHex, _ := hex.DecodeString(sig.Sig)

  // SecSysLib uses a SaltLength of `hashes.SHA256().digest_size`, i.e. 32
  result := rsa.VerifyPSS(rsaPub, crypto.SHA256, hashed[:], sigHex,
    &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})

  if result != nil {
    panic("Signature verification failed")
  } else {
    fmt.Println("Signature verification passed")
  }
}
