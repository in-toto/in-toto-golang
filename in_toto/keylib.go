package in_toto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
)

// ErrFailedPEMParsing gets returned when PKCS1, PKCS8 or PKIX key parsing fails
var ErrFailedPEMParsing = errors.New("failed parsing the PEM block: unsupported PEM type")

// ErrNoPEMBlock gets triggered when there is no PEM block in the provided file
var ErrNoPEMBLock = errors.New("failed to decode the data as PEM block (are you sure this is a pem file?)")

// ErrUnsupportedKeyType is returned when we are dealing with a key type different to ed25519 or RSA
var ErrUnsupportedKeyType = errors.New("unsupported key type")

/*
GenerateKeyId creates a partial key map and generates the key ID
based on the created partial key map via the SHA256 method.
The resulting keyID will be directly saved in the corresponding key object.
On success GenerateKeyId will return nil, in case of errors while encoding
there will be an error.
*/
func (k *Key) GenerateKeyId() error {
	// Create partial key map used to create the keyid
	// Unfortunately, we can't use the Key object because this also carries
	// yet unwanted fields, such as KeyId and KeyVal.Private and therefore
	// produces a different hash. We generate the keyId exactly as we do in
	// the securesystemslib  to keep interoperability between other in-toto
	// implementations.
	var keyToBeHashed = map[string]interface{}{
		"keytype":               k.KeyType,
		"scheme":                k.Scheme,
		"keyid_hash_algorithms": k.KeyIdHashAlgorithms,
		"keyval": map[string]string{
			"public": k.KeyVal.Public,
		},
	}
	keyCanonical, err := EncodeCanonical(keyToBeHashed)
	if err != nil {
		return err
	}
	// calculate sha256 and return string representation of keyId
	keyHashed := sha256.Sum256(keyCanonical)
	k.KeyId = fmt.Sprintf("%x", keyHashed)
	return nil
}

/*
GeneratePublicPemBlock creates a "PUBLIC KEY" PEM block from public key byte data.
If successful it returns PEM block as []byte slice. This function should always
succeed, if pubKeyBytes is empty the PEM block will have an empty byte block.
Therefore only header and footer will exist.
*/
func GeneratePublicPemBlock(pubKeyBytes []byte) []byte {
	// construct PEM block
	publicKeyPemBlock := &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubKeyBytes,
	}
	return pem.EncodeToMemory(publicKeyPemBlock)
}

/*
SetKeyComponents sets all components in our key object.
Furthermore it makes sure to remove any trailing and leading whitespaces or newlines.
*/
func (k *Key) SetKeyComponents(pubKeyBytes []byte, privateKeyBytes []byte, keyType string, scheme string, keyIdHashAlgorithms []string) error {
	if len(privateKeyBytes) > 0 {
		// assume we have a privateKey
		k.KeyVal = KeyVal{
			Private: strings.TrimSpace(string(privateKeyBytes)),
			Public:  strings.TrimSpace(string(GeneratePublicPemBlock(pubKeyBytes))),
		}
	} else {
		k.KeyVal = KeyVal{
			Public: strings.TrimSpace(string(pubKeyBytes)),
		}
	}
	k.KeyType = keyType
	k.Scheme = scheme
	k.KeyIdHashAlgorithms = keyIdHashAlgorithms
	if err := k.GenerateKeyId(); err != nil {
		return err
	}
	return nil
}

/*
ParseKey tries to parse a PEM []byte slice.
Supported are:

	* PKCS8
	* PKCS1
	* PKIX

On success it returns the parsed key and nil.
On failure it returns nil and the error ErrFailedPEMParsing
*/
func ParseKey(data []byte) (interface{}, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS1PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}
	return nil, ErrFailedPEMParsing
}

/*
LoadKey loads the key file at specified file path into the key object.
It automatically derives the PEM type and the key type.
Right now the following PEM types are supported:

	* PKCS1 for private keys
	* PKCS8	for private keys
	* PKIX for public keys

The following key types are supported:

	* ed25519
	* RSA

On success it will return nil. The following errors can happen:

	* path not found or not readable
	* no PEM block in the loaded file
	* no valid PKCS8/PKCS1 private key or PKIX public key
	* errors while marshalling
	* unsupported key types
*/
func (k *Key) LoadKey(path string, scheme string, keyIdHashAlgorithms []string) error {
	pemFile, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := pemFile.Close(); closeErr != nil {
			err = closeErr
		}
	}()
	// Read key bytes and decode PEM
	pemBytes, err := ioutil.ReadAll(pemFile)
	if err != nil {
		return err
	}

	// TODO: There could be more key data in _, which we silently ignore here.
	// Should we handle it / fail / say something about it?
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return ErrNoPEMBLock
	}

	// Try to load private key, if this fails try to load
	// key as public key
	key, err := ParseKey(data.Bytes)
	if err != nil {
		return err
	}

	// Use type switch to identify the key format
	switch key.(type) {
	case *rsa.PublicKey:
		if err := k.SetKeyComponents(pemBytes, []byte{}, "rsa", scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case *rsa.PrivateKey:
		// Note: We store the public key as PKCS8 key here, although the private key get's stored as PKCS1 key
		// This behavior is consistent to the securesystemslib
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.(*rsa.PrivateKey).Public())
		if err != nil {
			return err
		}
		if err := k.SetKeyComponents(pubKeyBytes, pemBytes, "rsa", scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case *ed25519.PublicKey:
		if err := k.SetKeyComponents(pemBytes, []byte{}, "ed25519", scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	case *ed25519.PrivateKey:
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.(*ed25519.PrivateKey).Public())
		if err != nil {
			return err
		}
		if err := k.SetKeyComponents(pubKeyBytes, pemBytes, "ed25519", scheme, keyIdHashAlgorithms); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: %T", ErrUnsupportedKeyType, key)
	}
	return nil
}

/*
ParseRSAPublicKeyFromPEM parses the passed pemBytes as e.g. read from a PEM
formatted file, and instantiates and returns the corresponding RSA public key.
If no RSA public key can be parsed, the first return value is nil and the
second return value is the error.
*/
func ParseRSAPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	// TODO: There could be more key data in _, which we silently ignore here.
	// Should we handle it / fail / say something about it?
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, ErrNoPEMBLock
	}

	pub, err := x509.ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	//ParsePKIXPublicKey might return an rsa, dsa, or ecdsa public key
	rsaPub, isRsa := pub.(*rsa.PublicKey)
	if !isRsa {
		return nil, fmt.Errorf("We currently only support rsa keys: got '%s'",
			reflect.TypeOf(pub))
	}

	return rsaPub, nil
}

/*
ParseRSAPrivateKeyFromPEM parses the passed pemBytes as e.g. read from a PEM
formatted file, and instantiates and returns the corresponding RSA Private key.
If no RSA Private key can be parsed, the first return value is nil and the
second return value is the error.
*/
func ParseRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	// TODO: There could be more key data in _, which we silently ignore here.
	// Should we handle it / fail / say something about it?
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return nil, ErrNoPEMBLock
	}

	priv, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

/*
GenerateSignature will automatically detect the key type and sign the signable data
with the provided key. If everything goes right GenerateSignature will return
a for the key valid signature and err=nil. If something goes wrong it will
return an not initialized signature and an error. Possible errors are:

	* ErrNoPEMBlock
	* ErrUnsupportedKeyType

*/
func GenerateSignature(signable []byte, key Key) (Signature, error) {
	var signature Signature
	keyReader := strings.NewReader(key.KeyVal.Private)
	pemBytes, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return signature, err
	}
	// TODO: There could be more key data in _, which we silently ignore here.
	// Should we handle it / fail / say something about it?
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return signature, ErrNoPEMBLock
	}
	parsedKey, err := ParseKey(data.Bytes)
	if err != nil {
		return signature, err
	}

	var signatureBuffer []byte
	// Go type switch for interfering the key type
	switch parsedKey.(type) {
	case *rsa.PrivateKey:
		hashed := sha256.Sum256(signable)
		// We use rand.Reader as secure random source for rsa.SignPSS()
		signatureBuffer, err = rsa.SignPSS(rand.Reader, parsedKey.(*rsa.PrivateKey), crypto.SHA256, hashed[:],
			&rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
		if err != nil {
			return signature, err
		}
	case *ed25519.PrivateKey:
		// TODO: implement signatures for ed25519 keys
	default:
		return signature, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, parsedKey)
	}
	signature.Sig = hex.EncodeToString(signatureBuffer)
	signature.KeyId = key.KeyId
	return signature, nil
}

/*
GenerateRSASignature generates a rsassa-pss signature, based
on the passed key and signable data. If something goes wrong
it will return an uninitialized Signature with an error.
If everything goes right, the function will return an initialized
signature with err=nil.
*/
func GenerateRSASignature(signable []byte, key Key) (Signature, error) {
	var signature Signature
	keyReader := strings.NewReader(key.KeyVal.Private)
	pemBytes, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return signature, err
	}
	rsaPriv, err := ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		return signature, err
	}

	hashed := sha256.Sum256(signable)

	// We use rand.Reader as secure random source for rsa.SignPSS()
	signatureBuffer, err := rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, hashed[:],
		&rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
	if err != nil {
		return signature, err
	}

	signature.Sig = hex.EncodeToString(signatureBuffer)
	signature.KeyId = key.KeyId

	return signature, nil
}

/*
VerifyRSASignature uses the passed Key to verify the passed Signature over the
passed data.  It returns an error if the key is not a valid RSA public key or
if the signature is not valid for the data.
*/
func VerifyRSASignature(key Key, sig Signature, data []byte) error {
	// Create rsa.PublicKey object from DER encoded public key string as
	// found in the public part of the keyval part of a securesystemslib key dict
	keyReader := strings.NewReader(key.KeyVal.Public)
	pemBytes, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return err
	}
	rsaPub, err := ParseRSAPublicKeyFromPEM(pemBytes)
	if err != nil {
		return err
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

/*
ParseEd25519FromPrivateJSON parses an ed25519 private key from the json string.
These ed25519 keys have the format as generated using in-toto-keygen:

	{
		"keytype: "ed25519",
		"scheme": "ed25519",
		"keyid": ...
		"keyid_hash_algorithms": [...]
		"keyval": {
			"public": "..." # 32 bytes
			"private": "..." # 32 bytes
		}
	}
*/
func ParseEd25519FromPrivateJSON(JSONString string) (Key, error) {
	var keyObj Key
	err := json.Unmarshal([]uint8(JSONString), &keyObj)
	if err != nil {
		return keyObj, fmt.Errorf("this is not a valid JSON key object")
	}

	if keyObj.KeyType != "ed25519" || keyObj.Scheme != "ed25519" {
		return keyObj, fmt.Errorf("this doesn't appear to be an ed25519 key")
	}

	// if the keyId is empty we try to generate the keyId
	if keyObj.KeyId == "" {
		if err := keyObj.GenerateKeyId(); err != nil {
			return keyObj, err
		}
	}

	if err := validatePrivateKey(keyObj); err != nil {
		return keyObj, err
	}

	// 64 hexadecimal digits => 32 bytes for the private portion of the key
	if len(keyObj.KeyVal.Private) != 64 {
		return keyObj, fmt.Errorf("the private field on this key is malformed")
	}

	return keyObj, nil
}

/*
ParseEd25519FromPublicJSON parses an ed25519 public key from the json string.
These ed25519 keys have the format as generated using in-toto-keygen:

	{
		"keytype": "ed25519",
		"scheme": "ed25519",
		"keyid_hash_algorithms": [...],
		"keyval": {"public": "..."}
	}

*/
func ParseEd25519FromPublicJSON(JSONString string) (Key, error) {
	var keyObj Key
	err := json.Unmarshal([]uint8(JSONString), &keyObj)
	if err != nil {
		return keyObj, fmt.Errorf("this is not a valid JSON key object")
	}

	if keyObj.KeyType != "ed25519" || keyObj.Scheme != "ed25519" {
		return keyObj, fmt.Errorf("this doesn't appear to be an ed25519 key")
	}

	// if the keyId is empty we try to generate the keyId
	if keyObj.KeyId == "" {
		if err := keyObj.GenerateKeyId(); err != nil {
			return keyObj, err
		}
	}

	if err := validatePubKey(keyObj); err != nil {
		return keyObj, err
	}

	// 64 hexadecimal digits => 32 bytes for the public portion of the key
	if len(keyObj.KeyVal.Public) != 64 {
		return keyObj, fmt.Errorf("the public field on this key is malformed")
	}

	return keyObj, nil
}

/*
GenerateEd25519Signature creates an ed25519 signature using the key and the
signable buffer provided. It returns an error if the underlying signing library
fails.
*/
func GenerateEd25519Signature(signable []byte, key Key) (Signature, error) {

	var signature Signature

	seed, err := hex.DecodeString(key.KeyVal.Private)
	if err != nil {
		return signature, err
	}
	privkey := ed25519.NewKeyFromSeed(seed)
	signatureBuffer := ed25519.Sign(privkey, signable)

	signature.Sig = hex.EncodeToString(signatureBuffer)
	signature.KeyId = key.KeyId

	return signature, nil
}

/*
VerifyEd25519Signature uses the passed Key to verify the passed Signature over the
passed data. It returns an error if the key is not a valid ed25519 public key or
if the signature is not valid for the data.
*/
func VerifyEd25519Signature(key Key, sig Signature, data []byte) error {
	pubHex, err := hex.DecodeString(key.KeyVal.Public)
	if err != nil {
		return err
	}
	sigHex, err := hex.DecodeString(sig.Sig)
	if err != nil {
		return err
	}
	if ok := ed25519.Verify(pubHex, data, sigHex); !ok {
		return errors.New("invalid ed25519 signature")
	}
	return nil
}
