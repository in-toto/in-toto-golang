package in_toto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"os"
	"strings"
)

// ErrFailedPEMParsing gets returned when PKCS1, PKCS8 or PKIX key parsing fails
var ErrFailedPEMParsing = errors.New("failed parsing the PEM block: unsupported PEM type")

// ErrNoPEMBlock gets triggered when there is no PEM block in the provided file
var ErrNoPEMBLock = errors.New("failed to decode the data as PEM block (are you sure this is a pem file?)")

// ErrUnsupportedKeyType is returned when we are dealing with a key type different to ed25519 or RSA
var ErrUnsupportedKeyType = errors.New("unsupported key type")

// ErrInvalidSignature is returned when the signature is invalid
var ErrInvalidSignature = errors.New("invalid signature")

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
		signatureBuffer = ed25519.Sign(parsedKey.(ed25519.PrivateKey), signable)
	default:
		return signature, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, parsedKey)
	}
	signature.Sig = hex.EncodeToString(signatureBuffer)
	signature.KeyId = key.KeyId
	return signature, nil
}

func VerifySignature(key Key, sig Signature, unverified []byte) error {
	// Create rsa.PublicKey object from DER encoded public key string as
	// found in the public part of the keyval part of a securesystemslib key dict
	keyReader := strings.NewReader(key.KeyVal.Public)
	pemBytes, err := ioutil.ReadAll(keyReader)
	if err != nil {
		return err
	}
	// TODO: There could be more key data in _, which we silently ignore here.
	// Should we handle it / fail / say something about it?
	data, _ := pem.Decode(pemBytes)
	if data == nil {
		return ErrNoPEMBLock
	}
	parsedKey, err := ParseKey(data.Bytes)
	if err != nil {
		return err
	}
	switch parsedKey.(type) {
	case *rsa.PublicKey:
		hashed := sha256.Sum256(unverified)
		sigHex, _ := hex.DecodeString(sig.Sig)
		err := rsa.VerifyPSS(parsedKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], sigHex, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidSignature, err)
		}
	case *ed25519.PublicKey:
		sigHex, err := hex.DecodeString(sig.Sig)
		if err != nil {
			return err
		}
		if ok := ed25519.Verify(parsedKey.(ed25519.PublicKey), unverified, sigHex); !ok {
			return fmt.Errorf("%w: ed25519", ErrInvalidSignature)
		}
	default:
		return fmt.Errorf("%w: Key has type %T", ErrInvalidSignature, parsedKey)
	}
	return nil
}
