package in_toto

import (
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"rsa public key", "alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680"},
		{"rsa private key", "dan", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"},
		{"rsa public key", "dan.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"},
		{"ed25519 private key", "carol", "ed25519", []string{"sha256", "sha512"}, "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6"},
		{"ed25519 public key", "carol.pub", "ed25519", []string{"sha256", "sha512"}, "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6"},
		{"ecdsa private key (P521)", "frank", "ecdsa-sha2-nistp521", []string{"sha256", "sha512"}, "434cf7c5b168f6ea4c7e6e67afa74a02625310530f1664f761637bdc7ad8f8df"},
		{"ecdsa public key (P521)", "frank.pub", "ecdsa-sha2-nistp521", []string{"sha256", "sha512"}, "434cf7c5b168f6ea4c7e6e67afa74a02625310530f1664f761637bdc7ad8f8df"},
		{"ecdsa private key (P384)", "grace", "ecdsa-sha2-nistp384", []string{"sha256", "sha512"}, "a5522ebccd492f64e6ec0bbcb5eb782708f6e26709a3712e64fff108b98e5142"},
		{"ecdsa public key (P384)", "grace.pub", "ecdsa-sha2-nistp384", []string{"sha256", "sha512"}, "a5522ebccd492f64e6ec0bbcb5eb782708f6e26709a3712e64fff108b98e5142"},
		{"ecdsa private key (P224)", "heidi", "ecdsa-sha2-nistp224", []string{"sha256", "sha512"}, "fae849ef9247cc7d19ebd33ab63b5d18a31357508fd82d8ad2aad6fdcc584bd7"},
		{"ecdsa public key (P224)", "heidi.pub", "ecdsa-sha2-nistp224", []string{"sha256", "sha512"}, "fae849ef9247cc7d19ebd33ab63b5d18a31357508fd82d8ad2aad6fdcc584bd7"},
		{"rsa public key from certificate", "example.com.write-code.cert.pem", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "4979dea7a8467cbe0299693703b81d490854143b859a469ec0f6349e7bdf582a"},
	}
	for _, table := range validTables {
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.hashAlgorithms)
		if err != nil {
			t.Errorf("failed key.LoadKey() for %s %s. Error: %s", table.name, table.path, err)
		}
		if table.expectedKeyID != key.KeyID {
			t.Errorf("keyID for %s %s does not match expected keyID: %s. Got keyID: %s", table.name, table.path, table.expectedKeyID, key.KeyID)
		}
	}
}

// TestLoadKeyDefaults makes sure our function loads keys correctly
// with the expected default schemes
func TestLoadKeyDefaults(t *testing.T) {
	validTables := []struct {
		name           string
		path           string
		expectedKeyID  string
		expectedScheme string
	}{
		{"rsa public key", "alice.pub", "70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680", rsassapsssha256Scheme},
		{"rsa private key", "dan", "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401", rsassapsssha256Scheme},
		{"rsa public key", "dan.pub", "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401", rsassapsssha256Scheme},
		{"ed25519 private key", "carol", "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6", ed25519Scheme},
		{"ed25519 public key", "carol.pub", "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6", ed25519Scheme},
		{"ecdsa private key (P521)", "frank", "0ab02fd8a1195d902d4e71df38123be0d3fa9ea45ebc6e1246d8e82179acb6dd", ecdsaSha2nistp256},
		{"ecdsa public key (P521)", "frank.pub", "0ab02fd8a1195d902d4e71df38123be0d3fa9ea45ebc6e1246d8e82179acb6dd", ecdsaSha2nistp256},
		{"ecdsa private key (P384)", "grace", "a5fe82bffd11c43cd25b41b427496dea8eb61505bfa11907a6a565ebb00fa323", ecdsaSha2nistp256},
		{"ecdsa public key (P384)", "grace.pub", "a5fe82bffd11c43cd25b41b427496dea8eb61505bfa11907a6a565ebb00fa323", ecdsaSha2nistp256},
		{"ecdsa private key (P224)", "heidi", "337f2a2bed46e863a68f17ae0e3e96756eca87c38080d872c5824493cec1ce1a", ecdsaSha2nistp256},
		{"ecdsa public key (P224)", "heidi.pub", "337f2a2bed46e863a68f17ae0e3e96756eca87c38080d872c5824493cec1ce1a", ecdsaSha2nistp256},
		{"rsa public key from certificate", "example.com.write-code.cert.pem", "4979dea7a8467cbe0299693703b81d490854143b859a469ec0f6349e7bdf582a", rsassapsssha256Scheme},
	}
	for _, table := range validTables {
		var key Key
		err := key.LoadKeyDefaults(table.path)
		if err != nil {
			t.Errorf("failed key.LoadKeyDefaults() for %s %s. Error: %s", table.name, table.path, err)
		}
		if table.expectedKeyID != key.KeyID {
			t.Errorf("keyID for %s %s does not match expected keyID: %s. Got keyID: %s", table.name, table.path, table.expectedKeyID, key.KeyID)
		}
		if table.expectedScheme != key.Scheme {
			t.Errorf("scheme for %s %s does not match expected scheme: %s. Got scheme %s", table.name, table.path, table.expectedScheme, key.Scheme)
		}
	}
}

// TestLoadKeyReader makes sure, that our LoadKeyReader function loads keys correctly
// and that the key IDs of private and public key match.
func TestLoadKeyReader(t *testing.T) {
	var key Key
	if err := key.LoadKeyReader(nil, "ed25519", []string{"sha256", "sha512"}); err != ErrNoPEMBlock {
		t.Errorf("unexpected error loading key: %s", err)
	}
}

// TestLoadKeyErrors tests the LoadKey functions for the most popular errors:
//
//   - os.ErrNotExist (triggered, when the file does not exist)
//   - ErrNoPEMBlock (for example if the passed file is not a PEM block)
//   - ErrFailedPEMParsing (for example if we pass an EC key, instead a key in PKCS8 format)
func TestLoadKeyErrors(t *testing.T) {
	invalidTables := []struct {
		name           string
		path           string
		scheme         string
		hashAlgorithms []string
		err            error
	}{
		{"not existing file", "inToToRocks", "rsassa-pss-sha256", []string{"sha256", "sha512"}, os.ErrNotExist},
		{"existing, but invalid file", "demo.layout", "ecdsa-sha2-nistp521", []string{"sha512"}, ErrNoPEMBlock},
		{"EC private key file", "erin", "ecdsa-sha2-nistp521", []string{"sha256", "sha512"}, ErrFailedPEMParsing},
		{"valid ed25519 private key, but invalid scheme", "carol", "", []string{"sha256"}, ErrEmptyKeyField},
		{"valid ed25519 public key, but invalid scheme", "carol.pub", "", []string{"sha256"}, ErrEmptyKeyField},
		{"valid rsa private key, but invalid scheme", "dan", "rsassa-psa-sha256", nil, ErrSchemeKeyTypeMismatch},
		{"valid rsa public key, but invalid scheme", "dan.pub", "rsassa-psa-sha256", nil, ErrSchemeKeyTypeMismatch},
		{"valid ecdsa private key, but invalid scheme", "frank", "ecdsa-sha-nistp256", nil, ErrSchemeKeyTypeMismatch},
		{"valid ecdsa public key, but invalid scheme", "frank.pub", "ecdsa-sha-nistp256", nil, ErrSchemeKeyTypeMismatch},
	}

	for _, table := range invalidTables {
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.hashAlgorithms)
		if !errors.Is(err, table.err) {
			t.Errorf("failed LoadKey() for %s %s, got error: %s. Should have: %s", table.name, table.path, err, table.err)
		}
	}
}

// TestLoadKeyDefaultsErrors tests the LoadKeyDefaults functions for the most popular errors:
//
//   - os.ErrNotExist (triggered, when the file does not exist)
//   - ErrNoPEMBlock (for example if the passed file is not a PEM block)
//   - ErrFailedPEMParsing (for example if we pass an EC key, instead a key in PKCS8 format)
func TestLoadKeyDefaultsErrors(t *testing.T) {
	invalidTables := []struct {
		name string
		path string
		err  error
	}{
		{"not existing file", "inToToRocks", os.ErrNotExist},
		{"existing, but invalid file", "demo.layout", ErrNoPEMBlock},
		{"EC private key file", "erin", ErrFailedPEMParsing},
	}

	for _, table := range invalidTables {
		var key Key
		err := key.LoadKeyDefaults(table.path)
		if !errors.Is(err, table.err) {
			t.Errorf("failed LoadKeyDefaults() for %s %s, got error: %s. Should have: %s", table.name, table.path, err, table.err)
		}
	}
}

func TestSetKeyComponentsErrors(t *testing.T) {
	invalidTables := []struct {
		name                string
		pubkeyBytes         []byte
		privateKeyBytes     []byte
		keyType             string
		scheme              string
		KeyIDHashAlgorithms []string
		err                 error
	}{
		{"test invalid key type", []byte{}, []byte{}, "yolo", "ed25519", []string{"sha512"}, ErrUnsupportedKeyType},
		{"invalid scheme", []byte("393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c"), []byte{}, "ed25519", "", []string{"sha256"}, ErrEmptyKeyField},
	}

	for _, table := range invalidTables {
		var key Key
		err := key.setKeyComponents(table.pubkeyBytes, table.privateKeyBytes, table.keyType, table.scheme, table.KeyIDHashAlgorithms)
		if !errors.Is(err, table.err) {
			t.Errorf("'%s' failed, should have: '%s', got: '%s'", table.name, ErrUnsupportedKeyType, err)
		}
	}
}

func TestVerifyCertificateTrust(t *testing.T) {
	var rootKey, intermediateKey, leafKey Key
	err := rootKey.LoadKeyDefaults("root.cert.pem")
	assert.Nil(t, err, "unexpected error loading root")
	err = intermediateKey.LoadKeyDefaults("example.com.intermediate.cert.pem")
	assert.Nil(t, err, "unexpected error loading intermediate")
	err = leafKey.LoadKeyDefaults("example.com.write-code.cert.pem")
	assert.Nil(t, err, "unexpected error loading leaf")

	rootPool := x509.NewCertPool()
	ok := rootPool.AppendCertsFromPEM([]byte(rootKey.KeyVal.Certificate))
	assert.True(t, ok, "unexpected error adding cert to root pool")
	intermediatePool := x509.NewCertPool()
	ok = intermediatePool.AppendCertsFromPEM([]byte(intermediateKey.KeyVal.Certificate))
	assert.True(t, ok, "unexpected error adding cert to root pool")

	_, possibleLeafCert, err := decodeAndParse([]byte(leafKey.KeyVal.Certificate))
	assert.Nil(t, err, "unexpected error parsing leaf certificate")
	leafCert, ok := possibleLeafCert.(*x509.Certificate)
	assert.True(t, ok, "parseKey didn't return a x509 certificate")

	// Test the happy path
	_, err = VerifyCertificateTrust(leafCert, rootPool, intermediatePool)
	assert.Nil(t, err, "unexpected error verifying trust")

	// Test with no intermediate connecting the leaf to the root
	_, err = VerifyCertificateTrust(leafCert, rootPool, x509.NewCertPool())
	assert.NotNil(t, err, "expected error with missing intermediate")

	// Test with no root
	_, err = VerifyCertificateTrust(leafCert, x509.NewCertPool(), intermediatePool)
	assert.NotNil(t, err, "expected error with missing root")
}
