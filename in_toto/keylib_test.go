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
		{"rsa public key", "alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "d7b728368798278c6bbd43e57b9ff9794be73c24edc574fdaae67efcbc34e23a"},
		{"rsa private key", "dan", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "7223226fff4de04198b71f5e4ed6897d77d5e2ee928ef609d0e3efeca9f3dd9b"},
		{"rsa public key", "dan.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "7223226fff4de04198b71f5e4ed6897d77d5e2ee928ef609d0e3efeca9f3dd9b"},
		{"ed25519 private key", "carol", "ed25519", []string{"sha256", "sha512"}, "41d55e82a05090d8129880e38b9b82acb9cef4990b3594030bb674d61ec89c38"},
		{"ed25519 public key", "carol.pub", "ed25519", []string{"sha256", "sha512"}, "41d55e82a05090d8129880e38b9b82acb9cef4990b3594030bb674d61ec89c38"},
		{"ecdsa private key (P521)", "frank", "ecdsa-sha2-nistp521", []string{"sha256", "sha512"}, "31090a6ae8a7f9e028e0384802ac1318fd0897e9913d0f54c3f99e1316347bd7"},
		{"ecdsa public key (P521)", "frank.pub", "ecdsa-sha2-nistp521", []string{"sha256", "sha512"}, "31090a6ae8a7f9e028e0384802ac1318fd0897e9913d0f54c3f99e1316347bd7"},
		{"ecdsa private key (P384)", "grace", "ecdsa-sha2-nistp384", []string{"sha256", "sha512"}, "2e43a67f17b0064fecf5d3ec56f04a4372c6d36361ca8089196a3e646494f1e8"},
		{"ecdsa public key (P384)", "grace.pub", "ecdsa-sha2-nistp384", []string{"sha256", "sha512"}, "2e43a67f17b0064fecf5d3ec56f04a4372c6d36361ca8089196a3e646494f1e8"},
		{"ecdsa private key (P224)", "heidi", "ecdsa-sha2-nistp224", []string{"sha256", "sha512"}, "e60d9cfdf5ad4db9f270c3f06611b2a0bd318f29fef62626ccc286c5f8ff6fd1"},
		{"ecdsa public key (P224)", "heidi.pub", "ecdsa-sha2-nistp224", []string{"sha256", "sha512"}, "e60d9cfdf5ad4db9f270c3f06611b2a0bd318f29fef62626ccc286c5f8ff6fd1"},
		{"rsa public key from certificate", "example.com.write-code.cert.pem", "rsassa-pss-sha256", []string{"sha256", "sha512"}, "77367c76505915d0536e59de5643350b7b0cee489caf2a90b404a430be80d053"},
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
		{"rsa public key", "alice.pub", "d7b728368798278c6bbd43e57b9ff9794be73c24edc574fdaae67efcbc34e23a", rsassapsssha256Scheme},
		{"rsa private key", "dan", "7223226fff4de04198b71f5e4ed6897d77d5e2ee928ef609d0e3efeca9f3dd9b", rsassapsssha256Scheme},
		{"rsa public key", "dan.pub", "7223226fff4de04198b71f5e4ed6897d77d5e2ee928ef609d0e3efeca9f3dd9b", rsassapsssha256Scheme},
		{"ed25519 private key", "carol", "41d55e82a05090d8129880e38b9b82acb9cef4990b3594030bb674d61ec89c38", ed25519Scheme},
		{"ed25519 public key", "carol.pub", "41d55e82a05090d8129880e38b9b82acb9cef4990b3594030bb674d61ec89c38", ed25519Scheme},
		{"ecdsa private key (P521)", "frank", "fa4f1e140524c5c8f3b6097864e1e394409e0897dadf403d6637c45a174780d4", ecdsaSha2nistp256},
		{"ecdsa public key (P521)", "frank.pub", "fa4f1e140524c5c8f3b6097864e1e394409e0897dadf403d6637c45a174780d4", ecdsaSha2nistp256},
		{"ecdsa private key (P384)", "grace", "b079553155b0bc7216d6d500c71f7669fbfa93e6cb953f1c08e8853c87483927", ecdsaSha2nistp256},
		{"ecdsa public key (P384)", "grace.pub", "b079553155b0bc7216d6d500c71f7669fbfa93e6cb953f1c08e8853c87483927", ecdsaSha2nistp256},
		{"ecdsa private key (P224)", "heidi", "e08e48ea4bc13f8ca4e9eee97647c2bb5fa9a11a3082c167d2cf7dfed74e0269", ecdsaSha2nistp256},
		{"ecdsa public key (P224)", "heidi.pub", "e08e48ea4bc13f8ca4e9eee97647c2bb5fa9a11a3082c167d2cf7dfed74e0269", ecdsaSha2nistp256},
		{"rsa public key from certificate", "example.com.write-code.cert.pem", "77367c76505915d0536e59de5643350b7b0cee489caf2a90b404a430be80d053", rsassapsssha256Scheme},
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
		{"ecdsa private key (P521)", "frank", "ecdsa-sha2-nistp521", []string{"sha256", "sha512"}, `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`},
		{"ecdsa private key (P384)", "grace", "ecdsa-sha2-nistp384", []string{"sha256", "sha512"}, `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`},
		{"ecdsa private key (P224)", "heidi", "ecdsa-sha2-nistp224", []string{"sha256", "sha512"}, `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`},
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
//  * ErrFailedPEMParsing (for example if we pass an EC key, instead a key in PKCS8 format)
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
//	* os.ErrNotExist (triggered, when the file does not exist)
//	* ErrNoPEMBlock (for example if the passed file is not a PEM block)
//  * ErrFailedPEMParsing (for example if we pass an EC key, instead a key in PKCS8 format)
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

func TestGenerateSignatureErrors(t *testing.T) {
	invalidTables := []struct {
		name          string
		key           Key
		expectedError error
	}{
		{"invalid type", Key{
			KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIDHashAlgorithms: []string{"sha512"},
			KeyType:             "invalid",
			KeyVal: KeyVal{
				Private: "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICmtWWk/6UydYjr7tmVUtPa7JIxHdhaJraSHXr2pSECu\n-----END PRIVATE KEY-----",
				Public:  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----",
			},
			Scheme: "ed25519",
		}, ErrUnsupportedKeyType,
		},
		{
			"public key", Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha512"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----",
					Public:  "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICmtWWk/6UydYjr7tmVUtPa7JIxHdhaJraSHXr2pSECu\n-----END PRIVATE KEY-----",
				},
				Scheme: "ecdsa-sha2-nistp521",
			}, ErrKeyKeyTypeMismatch,
		},
		{
			"rsa private key, but wrong key type", Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			}, ErrSchemeKeyTypeMismatch,
		},
		{
			"ecdsa private key, but wrong key type", Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			}, ErrSchemeKeyTypeMismatch,
		},
		{
			"empty key", Key{}, ErrInvalidHexString,
		},
		{
			"invalid ec private key", Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			}, ErrFailedPEMParsing,
		},
		{"invalid ed25519 private key", Key{
			KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIDHashAlgorithms: []string{"sha512"},
			KeyType:             "ed25519",
			KeyVal: KeyVal{
				Private: "invalid",
				Public:  "invalid",
			},
			Scheme: "ed25519"},
			ErrInvalidHexString,
		},
		{
			name: "fail parsing RSA key, because of EC private key",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "rsassa-pss-sha256",
			},
			expectedError: ErrFailedPEMParsing,
		},
		{
			name: "RSA key, but with ecdsa values",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "rsassa-pss-sha256",
			},
			expectedError: ErrKeyKeyTypeMismatch,
		},
		{
			name: "p224 ecdsa key, but wrong scheme",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBwmUI9xaiYTFQU6OYl/jTnr\n+q2TfUh5LU8U4BrzoTwDOgAEu8hZFOOIyjE5FY71KsUbMOp6OB6e2T4dnFbo0Wrx\nrQFHFtW5Y3kiv6GEVF2mNDllRwJAoFpoF4M=\n-----END PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEu8hZFOOIyjE5FY71KsUbMOp6OB6e2T4d\nnFbo0WrxrQFHFtW5Y3kiv6GEVF2mNDllRwJAoFpoF4M=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			},
			expectedError: ErrCurveSizeSchemeMismatch,
		},
		{
			name: "p384 ecdsa key, but wrong scheme",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCgpTsIXQ7HswVRgS8Z\nPdSCaGrA87YwUctguSPjvCxy9+sP1791Qx5IYy3RkAzlx8+hZANiAAQ/wpAeooDd\nCGIZBLqOV+hNcmUZMZxfF3Yi2aapT/Ly6vJQ2xedXSdaWgKw5srRcAyswPWJa8dg\nxINXXg8/S9rAs36N9XuWtzkgnDLVoWE+V6shKDB7c6Csol0WSfwsa7Y=\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEP8KQHqKA3QhiGQS6jlfoTXJlGTGcXxd2\nItmmqU/y8uryUNsXnV0nWloCsObK0XAMrMD1iWvHYMSDV14PP0vawLN+jfV7lrc5\nIJwy1aFhPlerISgwe3OgrKJdFkn8LGu2\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			},
			expectedError: ErrCurveSizeSchemeMismatch,
		},
		{
			name: "p521 ecdsa key, but wrong scheme",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp384",
			},
			expectedError: ErrCurveSizeSchemeMismatch,
		},
	}

	for _, table := range invalidTables {
		_, err := GenerateSignature([]byte("test"), table.key)
		if !errors.Is(err, table.expectedError) {
			t.Errorf("test '%s' failed, should got error: '%s', but received: '%s'", table.name, table.expectedError, err)
		}
	}
}

func TestVerifySignatureErrors(t *testing.T) {
	invalidTables := []struct {
		name          string
		key           Key
		sig           Signature
		expectedError error
	}{
		{"invalid keytype", Key{}, Signature{}, ErrInvalidHexString},
		{"invalid rsa/ecdsa public key", Key{
			KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIDHashAlgorithms: nil,
			KeyType:             "rsa",
			KeyVal: KeyVal{
				Private: "",
				Public:  "",
			},
			Scheme: "rsassa-psa-sha256",
		}, Signature{}, ErrEmptyKeyField,
		},
		{
			"ec public key", Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			}, Signature{}, ErrFailedPEMParsing,
		},
		{
			"rsa private key as public key", Key{
				KeyID:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
					Public:  "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			}, Signature{}, ErrKeyKeyTypeMismatch,
		},
		{
			"invalid ecdsa signature", Key{
				KeyID:               "d4cd6865653c3aaa9b9eb865e0e45dd8ed58c98cb39c0145d500e009d9817c32",
				KeyIDHashAlgorithms: []string{"sha256", "sha512"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			}, Signature{
				KeyID: "d4cd6865653c3aaa9b9eb865e0e45dd8ed58c98cb39c0145d500e009d9817c32",
				Sig:   "308188824201fae620e5b53e878f2b5cc9b59b8246165ecf8fb3438115dff7ecd567106c707606dceac37ffe5fa531fc03ebe310ce9397d814f1d59c78ddd975123825f976141b824201bca2b5931850d0e8453c41d8a727f136d28a7683bad34c54643978ee066a1eab3403d9dd4e82641cd6325693ee32385aa7a0b5f239f53d8b8b1174f9751e1ee114",
			}, ErrInvalidSignature,
		},
		{
			"invalid ed25519 signature", Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256", "sha512"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "",
					Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
				},
				Scheme: "ed25519",
			}, Signature{
				KeyID: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				Sig:   "BAAAAAAD",
			}, ErrInvalidSignature,
		},
		{"invalid asn1 structure", Key{
			KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIDHashAlgorithms: []string{"sha256"},
			KeyType:             "ecdsa",
			KeyVal: KeyVal{
				Private: "",
				Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
			},
			Scheme: "ecdsa-sha2-nistp521",
		}, Signature{
			KeyID: "invalid",
			Sig:   "BAAAAAAD",
		}, ErrInvalidSignature,
		},
		{
			"ed25519 with invalid public key", Key{
				KeyID:               "invalid",
				KeyIDHashAlgorithms: nil,
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "invalid",
					Public:  "invalid",
				},
				Scheme: "ed25519",
			}, Signature{}, ErrInvalidHexString,
		},
		{
			"ed25519 with invalid signature", Key{
				KeyID:               "invalid",
				KeyIDHashAlgorithms: nil,
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "",
					Public:  "",
				},
				Scheme: "ed25519",
			}, Signature{
				KeyID: "invalid",
				Sig:   "invalid",
			}, ErrInvalidHexString,
		},
		{
			name: "rsa test invalid signature",
			key: Key{
				KeyID:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			},
			sig: Signature{
				KeyID: "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				Sig:   "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
			},
			expectedError: ErrInvalidSignature,
		},
		{
			name: "fail RSA parsing",
			key: Key{
				KeyID:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "rsassa-pss-sha256",
			},
			sig: Signature{
				KeyID: "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				Sig:   "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
			},
			expectedError: ErrFailedPEMParsing,
		},
		{
			name: "ecdsa Key, but RSA KeyVal",
			key: Key{
				KeyID:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "ecdsa-sha2-nistp521",
			},
			sig: Signature{
				KeyID: "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				Sig:   "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
			},
			expectedError: ErrKeyKeyTypeMismatch,
		},
		{
			name: "invalid hex string for ed25519",
			key: Key{
				KeyID:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "invalid",
					Public:  "invalid",
				},
				Scheme: "ed25519",
			},
			sig: Signature{
				KeyID: "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				Sig:   "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
			},
			expectedError: ErrInvalidHexString,
		},
		{
			name: "p224 ecdsa key, but wrong scheme",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBBwmUI9xaiYTFQU6OYl/jTnr\n+q2TfUh5LU8U4BrzoTwDOgAEu8hZFOOIyjE5FY71KsUbMOp6OB6e2T4dnFbo0Wrx\nrQFHFtW5Y3kiv6GEVF2mNDllRwJAoFpoF4M=\n-----END PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEu8hZFOOIyjE5FY71KsUbMOp6OB6e2T4d\nnFbo0WrxrQFHFtW5Y3kiv6GEVF2mNDllRwJAoFpoF4M=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			},
			expectedError: ErrCurveSizeSchemeMismatch,
		},
		{
			name: "p384 ecdsa key, but wrong scheme",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCgpTsIXQ7HswVRgS8Z\nPdSCaGrA87YwUctguSPjvCxy9+sP1791Qx5IYy3RkAzlx8+hZANiAAQ/wpAeooDd\nCGIZBLqOV+hNcmUZMZxfF3Yi2aapT/Ly6vJQ2xedXSdaWgKw5srRcAyswPWJa8dg\nxINXXg8/S9rAs36N9XuWtzkgnDLVoWE+V6shKDB7c6Csol0WSfwsa7Y=\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEP8KQHqKA3QhiGQS6jlfoTXJlGTGcXxd2\nItmmqU/y8uryUNsXnV0nWloCsObK0XAMrMD1iWvHYMSDV14PP0vawLN+jfV7lrc5\nIJwy1aFhPlerISgwe3OgrKJdFkn8LGu2\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp521",
			},
			expectedError: ErrCurveSizeSchemeMismatch,
		},
		{
			name: "p521 ecdsa key, but wrong scheme",
			key: Key{
				KeyID:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIDHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa-sha2-nistp384",
			},
			expectedError: ErrCurveSizeSchemeMismatch,
		},
	}
	for _, table := range invalidTables {
		err := VerifySignature(table.key, table.sig, []byte("invalid"))
		if !errors.Is(err, table.expectedError) {
			t.Errorf("test '%s' failed, should got error: '%s', but received: '%s'", table.name, table.expectedError, err)
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
