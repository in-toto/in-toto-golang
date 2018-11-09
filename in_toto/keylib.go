package in_toto

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
  "reflect"
)

func (k *Key) LoadPublicKey(path string) error {
  keyFile, err := os.Open(path)
  defer keyFile.Close()
  if err != nil {
    return err
  }

  // Read key bytes and decode PEM
  keyBytes, err := ioutil.ReadAll(keyFile)
  if err != nil {
    return err
  }

  // Parse just to see if this is a pem formatted key
  // TODO: There could be more key data in _, which we silently ignore here.
  // Should we handle it / fail / say something about it?
  data, _ := pem.Decode([]byte(keyBytes))
  if data == nil {
    return fmt.Errorf("No valid public rsa key found at '%s'", path)
  }

  // Parse just to see if this is indeed an rsa public key
  pub, err := x509.ParsePKIXPublicKey(data.Bytes)
  if err != nil {
    return err
  }
  _, isRsa := pub.(*rsa.PublicKey)
  if !isRsa {
    return fmt.Errorf("We currently only support rsa keys: got '%s'",
        reflect.TypeOf(pub))
  }

  // Strip leading and trailing data from PEM file like securesystemslib does
  // TODO: Should we instead use the parsed public key to reconstruct the PEM?
  keyHeader := "-----BEGIN PUBLIC KEY-----"
  keyFooter := "-----END PUBLIC KEY-----"
  keyStart := strings.Index(string(keyBytes), keyHeader)
  keyEnd := strings.Index(string(keyBytes), keyFooter) + len(keyFooter)

  // Fail if header and footer are not present
  // TODO: Is this necessary? pem.Decode or ParsePKIXPublicKey should already
  // return an error if header and footer are not present
  if keyStart == -1 || keyEnd == -1 {
    return fmt.Errorf("No valid public rsa key found at '%s'", path)
  }
  keyBytesStripped := keyBytes[keyStart:keyEnd]

  // Declare values for key
  // TODO: Do not hardcode here, but define defaults elsewhere and add support
  // for parametrization
  keyType := "rsa"
  scheme := "rsassa-pss-sha256"
  keyIdHashAlgorithms := []string{"sha256", "sha512"}

  // Create partial key map used to create the keyid
  // Unfortunately, we can't use the Key object because this also carries
  // yet unwanted fields, such as KeyId and KeyVal.Private and therefore
  // produces a different hash
  var keyToBeHashed = map[string]interface{}{
    "keytype": keyType,
    "scheme": scheme,
    "keyid_hash_algorithms": keyIdHashAlgorithms,
    "keyval": map[string]string{
      "public": string(keyBytesStripped),
    },
  }

  // Canonicalize key and get hex representation of hash
  keyCanonical, err := encode_canonical(keyToBeHashed)
  if err != nil {
    return err
  }
  keyHashed := sha256.Sum256(keyCanonical)

  // Unmarshalling the canonicalized key into the Key object would seem natural
  // Unfortunately, our mandated canonicalization function produces a byte
  // slice that cannot be unmarshalled by Golang's json decoder, hence we have
  // to manually assign the values
  k.KeyType = keyType
  k.KeyVal = KeyVal{
      Public: string(keyBytesStripped),
    }
  k.Scheme = scheme
  k.KeyIdHashAlgorithms = keyIdHashAlgorithms
  k.KeyId = fmt.Sprintf("%x", keyHashed)

  return nil
}


func VerifySignature(key Key, sig Signature, data []byte) error {
  // Create rsa.PublicKey object from DER encoded public key string as
  // found in the public part of the keyval part of a securesystemslib key dict
  keyReader := strings.NewReader(key.KeyVal.Public)
  pemBytes, err := ioutil.ReadAll(keyReader)
  if err != nil {
    return err
  }

  block, _ := pem.Decode(pemBytes)
  if block == nil {
    return fmt.Errorf("Could not find a public key PEM block")
  }

  pub, err := x509.ParsePKIXPublicKey(block.Bytes)
  if err != nil {
    return err
  }

  rsaPub, ok := pub.(*rsa.PublicKey)
  if !ok {
    return fmt.Errorf("Expected '*rsa.PublicKey' got '%s", reflect.TypeOf(pub))
  }

  hashed := sha256.Sum256(data)

  // Create hex bytes from the signature hex string
  sigHex, _ := hex.DecodeString(sig.Sig)

  // SecSysLib uses a SaltLength of `hashes.SHA256().digest_size`, i.e. 32
  if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, hashed[:], sigHex,
    &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}); err != nil {
    return err
  }

  return nil
}
