package in_toto

import (
	"errors"
	"os"
	"testing"
)

// TestLoadKey makes sure, that our LoadKey function loads keys correctly
// and that the key IDs of private and public key match.
func TestLoadKey(t *testing.T) {
	validTables := []struct {
		name           string
		path           string
		scheme         string
		hashAlgorithms []string
		expectedKeyID  string
	}{
		{"rsa public key", "alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b588f3e9cc48b35"},
		{"rsa private key", "dan", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"},
		{"rsa public key", "dan.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"},
		{"ed25519 private key", "carol", "ed25519", []string{"sha256", "sha512"}, "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6"},
		{"ed25519 public key", "carol.pub", "ed25519", []string{"sha256", "sha512"}, "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6"},
		{"ecdsa private key", "frank", "ecdsa", []string{"sha256", "sha512"}, "d4cd6865653c3aaa9b9eb865e0e45dd8ed58c98cb39c0145d500e009d9817c32"},
		{"ecdsa public key", "frank.pub", "ecdsa", []string{"sha256", "sha512"}, "d4cd6865653c3aaa9b9eb865e0e45dd8ed58c98cb39c0145d500e009d9817c32"},
	}
	for _, table := range validTables {
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.hashAlgorithms)
		if err != nil {
			t.Errorf("failed key.LoadKey() for %s %s. Error: %s", table.name, table.path, err)
		}
		if table.expectedKeyID != key.KeyId {
			t.Errorf("keyID for %s %s does not match expected keyID: %s. Got keyID: %s", table.name, table.path, table.expectedKeyID, key.KeyId)
		}
	}
}

// TestValidSignatures utilizes our TestLoadKey function, but does not check the expected keyID.
// Instead the test function generates a signature via GenerateSignature() over valid data and verifies the data
// via ValidateSignature() with the from the private key extracted public key. We know that our extracted public key
// is the same as our single public key because we have tested this in the TestLoadKey function.
func TestValidSignatures(t *testing.T) {
	validTables := []struct {
		name           string
		path           string
		scheme         string
		hashAlgorithms []string
		signable       string
	}{
		{"rsa private key", "dan", "rsassa-pss-sha256", []string{"sha256", "sha512"}, `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`},
		{"ed25519 private key", "carol", "ed25519", []string{"sha256", "sha512"}, `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`},
		{"ecdsa private key", "frank", "ecdsa", []string{"sha256", "sha512"}, `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`},
	}

	for _, table := range validTables {
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.hashAlgorithms)
		if err != nil {
			t.Errorf("failed key.LoadKey() for %s %s. Error: %s", table.name, table.path, err)
		}
		validSig, err := GenerateSignature([]byte(table.signable), key)
		if err != nil {
			t.Errorf("failed GenerateSignature() for %s %s. Error: %s", table.name, table.path, err)
		}
		// We can directly verify the signatures, because all our key objects have been created from a private key
		// therefore we are able to use the extracted public key for validating the signature.
		err = VerifySignature(key, validSig, []byte(table.signable))
		if err != nil {
			t.Errorf("failed VerifySignature() for %s %s. Error: %s", table.name, table.path, err)
		}
	}
}

// TestLoadKeyErrors tests the LoadKey functions for the most popular errors:
//
//	* os.ErrNotExist (triggered, when the file does not exist)
//	* ErrNoPEMBlock (for example if the passed file is not a PEM block)
//  * ErrFailedPEMParsing (for example if we pass an EC key, instead a key in PKC8 format)
func TestLoadKeyErrors(t *testing.T) {
	invalidTables := []struct {
		name           string
		path           string
		scheme         string
		hashAlgorithms []string
		err            error
	}{
		{"not existing file", "inToToRocks", "rsassa-pss-sha256", []string{"sha256", "sha512"}, os.ErrNotExist},
		{"existing, but invalid file", "demo.layout.template", "ecdsa", []string{"sha512"}, ErrNoPEMBlock},
		{"EC private key file", "erin", "ecdsa", []string{"sha256", "sha512"}, ErrFailedPEMParsing},
	}

	for _, table := range invalidTables {
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.hashAlgorithms)
		if !errors.Is(err, table.err) {
			t.Errorf("failed LoadKey() for %s %s, got error: %s. Should have: %s", table.name, table.path, err, table.err)
		}
	}
}
