package intoto

import (
  "os"
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

func (k *Key) LoadPublicKey(path string) {
  keyFile, _ := os.Open(path)
  defer keyFile.Close()

  // Read key bytes and decode PEM
  keyBytes, _ := ioutil.ReadAll(keyFile)
  data, _ := pem.Decode([]byte(keyBytes))

  // Try if this is a indeed a public key
  x509.ParsePKIXPublicKey(data.Bytes)

  // Strip leading and trailing data from PEM file like securesystemslib does
  // TODO: Should we instead use the parsed public key to recontsruct the PEM?
  keyHeader := "-----BEGIN PUBLIC KEY-----"
  keyFooter := "-----END PUBLIC KEY-----"
  keyStart := strings.Index(string(keyBytes), keyHeader)
  keyEnd := strings.Index(string(keyBytes), keyFooter) + len(keyFooter)
  keyBytesStripped := keyBytes[keyStart:keyEnd]

  // Declare values for key
  // FIXME: We sholud not hardcode these
  keyType := "rsa"
  scheme := "rsassa-pss-sha256"
  keyIdHashAlgorithms := []string{"sha256", "sha512"}

  // Create partial key map used to create the keyid
  // Unfortunately we can't use the Key object because this will also carry
  // yet unwanted fields, such as KeyId and KeyVal.Private and therefore
  // produce a different hash
  var keyToBeHashed = map[string]interface{}{
    "keytype": keyType,
    "scheme": scheme,
    "keyid_hash_algorithms": keyIdHashAlgorithms,
    "keyval": map[string]string{
      "public": string(keyBytesStripped),
    },
  }

  // Canonicalize key and get hex representation of hash
  keyCanonical := encode_canonical(keyToBeHashed)
  keyHashed := sha256.Sum256(keyCanonical)

  // Unmarshalling the canonicalized key into the Key object would seem natural
  // Unfortunately our mandated canonicalization function produces a bytestream
  // that cannot be unmarshalled by Golang's json decoder, hence we have to
  // manually assign the values
  k.KeyType = keyType
  k.KeyVal = KeyVal{
      Public: string(keyBytesStripped),
    }
  k.Scheme = scheme
  k.KeyIdHashAlgorithms = keyIdHashAlgorithms
  k.KeyId = fmt.Sprintf("%x", keyHashed)
}


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
