package in_toto

import (
	"encoding/asn1"
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
		{"valid ed25519 private key, but invalid scheme", "carol", "", []string{"sha256"}, ErrEmptyKeyField},
		{"valid ed25519 public key, but invalid scheme", "carol.pub", "", []string{"sha256"}, ErrEmptyKeyField},
		{"valid rsa private key, but invalid hashalgo", "dan", "rsassa-psa-sha256", nil, ErrEmptyKeyField},
		{"valid rsa public key, but invalid hashalgo", "dan.pub", "rsassa-psa-sha256", nil, ErrEmptyKeyField},
		{"valid ecdsa private key, but invalid hashalgo", "frank", "ecdsa", nil, ErrEmptyKeyField},
		{"valid ecdsa public key, but invalid hashalgo", "frank.pub", "ecdsa", nil, ErrEmptyKeyField},
	}

	for _, table := range invalidTables {
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.hashAlgorithms)
		if !errors.Is(err, table.err) {
			t.Errorf("failed LoadKey() for %s %s, got error: %s. Should have: %s", table.name, table.path, err, table.err)
		}
	}
}

func TestSetKeyComponents(t *testing.T) {
	invalidTables := []struct {
		name                string
		pubkeyBytes         []byte
		privateKeyBytes     []byte
		keyType             string
		scheme              string
		keyIdHashAlgorithms []string
		err                 error
	}{
		{"test invalid key type", []byte{}, []byte{}, "yolo", "ed25519", []string{"sha512"}, ErrUnsupportedKeyType},
		{"invalid scheme", []byte("393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c"), []byte{}, "ed25519", "", []string{"sha256"}, ErrEmptyKeyField},
	}

	for _, table := range invalidTables {
		var key Key
		err := key.SetKeyComponents(table.pubkeyBytes, table.privateKeyBytes, table.keyType, table.scheme, table.keyIdHashAlgorithms)
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
			KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIdHashAlgorithms: []string{"sha512"},
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
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha512"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----",
					Public:  "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEICmtWWk/6UydYjr7tmVUtPa7JIxHdhaJraSHXr2pSECu\n-----END PRIVATE KEY-----",
				},
				Scheme: "ecdsa",
			}, ErrInvalidKey,
		},
		{
			"rsa private key, but wrong key type", Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN RSA PRIVATE KEY-----\nMIIG5QIBAAKCAYEAyCTik98953hKl6+B6n5l8DVIDwDnvrJfpasbJ3+Rw66YcawO\nZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXPr3foPHF455TlrqPVfCZiFQ+O4Caf\nxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYzeUHH4tH9MNzqKWbbJoekBsDpCDIx\np1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcTvpfZVDbXazQ7VqZkidt7geWq2Bid\nOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2LFMQ04A1KnGn1jxO35/fd6/OW32n\njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5ujlvSDjyfZu7c5yUQ2asYfQPLvnj\nG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/Vk43riJs165TJGYGVuLUhIEhHgiQ\ntwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBfp8348k6vJtDMB093/t6V9sTGYQcS\nbgKPyEQo5Pk6Wd4ZAgMBAAECggGBAIb8YZiMA2tfNSfy5jNqhoQo223LFYIHOf05\nVvofzwbkdcqM2bVL1SpJ5d9MPr7Jio/VDJpfg3JUjdqFBkj7tJRK0eYaPgoq4XIU\n64JtPM+pi5pgUnfFsi8mwO1MXO7AN7hd/3J1RdLfanjEYS/ADB1nIVI4gIR5KrE7\nvujQqO8pIsI1YEnTLa+wqEA0fSDACfo90pLCjBz1clL6qVAzYmy0a46h4k5ajv7V\nAI/96OHmLYDLsRa1Z60T2K17Q7se0zmHSjfssLQ+d+0zdU5BK8wFn1n2DvCc310T\na0ip+V+YNT0FBtmknTobnr9S688bR8vfBK0q0JsZ1YataGyYS0Rp0RYeEInjKie8\nDIzGuYNRzEjrYMlIOCCY5ybo9mbRiQEQvlSunFAAoKyr8svwU8/e2HV4lXxqDY9v\nKZzxeNYVvX2ZUP3D/uz74VvUWe5fz+ZYmmHVW0erbQC8Cxv2Q6SG/eylcfiNDdLG\narf+HNxcvlJ3v7I2w79tqSbHPcJc1QKBwQD6E/zRYiuJCd0ydnJXPCzZ3dhs/Nz0\ny9QJXg7QyLuHPGEV6r2nIK/Ku3d0NHi/hWglCrg2m8ik7BKaIUjvwVI7M/E3gcZu\ngknmlWjt5QY+LLfQdVgBeqwJdqLHXtw2GAJch6LGSxIcZ5F+1MmqUbfElUJ4h/To\nno6CFGfmAc2n6+PSMWxHT6Oe/rrAFQ2B25Kl9kIrfAUeWhtLm+n0ARXo7wKr63rg\nyJBXwr5Rl3U1NJGnuagQqcS7zDdZ2Glaj1cCgcEAzOIwl5Z0I42vU+2z9e+23Tyc\nHnSyp7AaHLJeuv92T8j7sF8qV1brYQqqzUAGpIGR6OZ9Vj2niPdbtdAQpgcTav+9\nBY9Nyk6YDgsTuN+bQEWsM8VfMUFVUXQAdNFJT6VPO877Fi0PnWhqxVVzr7GuUJFM\nzTUSscsqT40Ht2v1v+qYM4EziPUtUlxUbfuc0RwtfbSpALJG+rpPjvdddQ4Xsdj0\nEIoq1r/0v+vo0Dbpdy63N0iYh9r9yHioiUdCPUgPAoHBAJhKL7260NRFQ4UFiKAD\nLzUF2lSUsGIK9nc15kPS2hCC/oSATTpHt4X4H8iOY7IOJdvY6VGoEMoOUU23U1le\nGxueiBjLWPHXOfXHqvykaebXCKFTtGJCOB4TNxG+fNAcUuPSXZfwA3l0wK/CGYU0\n+nomgzIvaT93v0UL9DGni3vlNPm9yziqEPQ0H7n1mCIqeuXCT413mw5exRyIODK1\nrogJdVEIt+3Hdc9b8tZxK5lZCBJiBy0OlZXfyR1XouDZRQKBwC1++N1gio+ukcVo\nXnL5dTjxkZVtwpJcF6BRt5l8yu/yqHlE2KkmYwRckwsa8Z6sKxN1w1VYQZC3pQTd\nnCTSI2y6N2Y5qUOIalmL+igud1IxZojkhjvwzxpUURmfs9Dc25hjYPxOq03/9t21\nGQhlw1ieu1hCNdGHVPDvV0xSy/J/DKc7RI9gKl1EpXb6zZrdz/g/GtxNuldI8gvE\nQFuS8o4KqD/X/qVLYPURVNSPrQ5LMGI1W7GnXn2a1YoOadYj3wKBwQCh+crvbhDr\njb2ud3CJfdCs5sS5SEKADiUcxiJPcypxhmu+7vhG1Nr6mT0SAYWaA36GDJkU7/Oo\nvoal+uigbOt/UugS1nQYnEzDRkTidQMm1gXVNcWRTBFTKwRP/Gd6yOp9BUHJlFCu\nM2q8HYFtmSqOele6xFOAUnHhwVx4QURJYa+S5A603Jm6ETv0+Y6xdHX/02vA+pRt\nlQqaoEO7ScdRrzjgvVxXkEY3nwLcWdM61/RZTL0+be8goDw5cWt+PaA=\n-----END RSA PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-psa-sha256",
			}, ErrKeyKeyTypeMismatch,
		},
		{
			"ecdsa private key, but wrong key type", Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa",
			}, ErrKeyKeyTypeMismatch,
		},
		{
			"empty key", Key{}, ErrInvalidHexString,
		},
		{
			"invalid ec private key", Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdas",
			}, ErrFailedPEMParsing,
		},
		{"invalid ed25519 private key", Key{
			KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIdHashAlgorithms: []string{"sha512"},
			KeyType:             "ed25519",
			KeyVal: KeyVal{
				Private: "invalid",
				Public:  "invalid",
			},
			Scheme: "ed25519"},
			ErrInvalidHexString,
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
			KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIdHashAlgorithms: nil,
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
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa",
			}, Signature{}, ErrFailedPEMParsing,
		},
		{
			"rsa private key as public key", Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
					Public:  "-----BEGIN RSA PRIVATE KEY-----\nMIIG5QIBAAKCAYEAyCTik98953hKl6+B6n5l8DVIDwDnvrJfpasbJ3+Rw66YcawO\nZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXPr3foPHF455TlrqPVfCZiFQ+O4Caf\nxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYzeUHH4tH9MNzqKWbbJoekBsDpCDIx\np1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcTvpfZVDbXazQ7VqZkidt7geWq2Bid\nOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2LFMQ04A1KnGn1jxO35/fd6/OW32n\njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5ujlvSDjyfZu7c5yUQ2asYfQPLvnj\nG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/Vk43riJs165TJGYGVuLUhIEhHgiQ\ntwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBfp8348k6vJtDMB093/t6V9sTGYQcS\nbgKPyEQo5Pk6Wd4ZAgMBAAECggGBAIb8YZiMA2tfNSfy5jNqhoQo223LFYIHOf05\nVvofzwbkdcqM2bVL1SpJ5d9MPr7Jio/VDJpfg3JUjdqFBkj7tJRK0eYaPgoq4XIU\n64JtPM+pi5pgUnfFsi8mwO1MXO7AN7hd/3J1RdLfanjEYS/ADB1nIVI4gIR5KrE7\nvujQqO8pIsI1YEnTLa+wqEA0fSDACfo90pLCjBz1clL6qVAzYmy0a46h4k5ajv7V\nAI/96OHmLYDLsRa1Z60T2K17Q7se0zmHSjfssLQ+d+0zdU5BK8wFn1n2DvCc310T\na0ip+V+YNT0FBtmknTobnr9S688bR8vfBK0q0JsZ1YataGyYS0Rp0RYeEInjKie8\nDIzGuYNRzEjrYMlIOCCY5ybo9mbRiQEQvlSunFAAoKyr8svwU8/e2HV4lXxqDY9v\nKZzxeNYVvX2ZUP3D/uz74VvUWe5fz+ZYmmHVW0erbQC8Cxv2Q6SG/eylcfiNDdLG\narf+HNxcvlJ3v7I2w79tqSbHPcJc1QKBwQD6E/zRYiuJCd0ydnJXPCzZ3dhs/Nz0\ny9QJXg7QyLuHPGEV6r2nIK/Ku3d0NHi/hWglCrg2m8ik7BKaIUjvwVI7M/E3gcZu\ngknmlWjt5QY+LLfQdVgBeqwJdqLHXtw2GAJch6LGSxIcZ5F+1MmqUbfElUJ4h/To\nno6CFGfmAc2n6+PSMWxHT6Oe/rrAFQ2B25Kl9kIrfAUeWhtLm+n0ARXo7wKr63rg\nyJBXwr5Rl3U1NJGnuagQqcS7zDdZ2Glaj1cCgcEAzOIwl5Z0I42vU+2z9e+23Tyc\nHnSyp7AaHLJeuv92T8j7sF8qV1brYQqqzUAGpIGR6OZ9Vj2niPdbtdAQpgcTav+9\nBY9Nyk6YDgsTuN+bQEWsM8VfMUFVUXQAdNFJT6VPO877Fi0PnWhqxVVzr7GuUJFM\nzTUSscsqT40Ht2v1v+qYM4EziPUtUlxUbfuc0RwtfbSpALJG+rpPjvdddQ4Xsdj0\nEIoq1r/0v+vo0Dbpdy63N0iYh9r9yHioiUdCPUgPAoHBAJhKL7260NRFQ4UFiKAD\nLzUF2lSUsGIK9nc15kPS2hCC/oSATTpHt4X4H8iOY7IOJdvY6VGoEMoOUU23U1le\nGxueiBjLWPHXOfXHqvykaebXCKFTtGJCOB4TNxG+fNAcUuPSXZfwA3l0wK/CGYU0\n+nomgzIvaT93v0UL9DGni3vlNPm9yziqEPQ0H7n1mCIqeuXCT413mw5exRyIODK1\nrogJdVEIt+3Hdc9b8tZxK5lZCBJiBy0OlZXfyR1XouDZRQKBwC1++N1gio+ukcVo\nXnL5dTjxkZVtwpJcF6BRt5l8yu/yqHlE2KkmYwRckwsa8Z6sKxN1w1VYQZC3pQTd\nnCTSI2y6N2Y5qUOIalmL+igud1IxZojkhjvwzxpUURmfs9Dc25hjYPxOq03/9t21\nGQhlw1ieu1hCNdGHVPDvV0xSy/J/DKc7RI9gKl1EpXb6zZrdz/g/GtxNuldI8gvE\nQFuS8o4KqD/X/qVLYPURVNSPrQ5LMGI1W7GnXn2a1YoOadYj3wKBwQCh+crvbhDr\njb2ud3CJfdCs5sS5SEKADiUcxiJPcypxhmu+7vhG1Nr6mT0SAYWaA36GDJkU7/Oo\nvoal+uigbOt/UugS1nQYnEzDRkTidQMm1gXVNcWRTBFTKwRP/Gd6yOp9BUHJlFCu\nM2q8HYFtmSqOele6xFOAUnHhwVx4QURJYa+S5A603Jm6ETv0+Y6xdHX/02vA+pRt\nlQqaoEO7ScdRrzjgvVxXkEY3nwLcWdM61/RZTL0+be8goDw5cWt+PaA=\n-----END RSA PRIVATE KEY-----",
				},
				Scheme: "rsassa-psa-sha256",
			}, Signature{}, ErrInvalidKey,
		},
		{
			"invalid ecdsa signature", Key{
				KeyId:               "d4cd6865653c3aaa9b9eb865e0e45dd8ed58c98cb39c0145d500e009d9817c32",
				KeyIdHashAlgorithms: []string{"sha256", "sha512"},
				KeyType:             "ecdsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
				},
				Scheme: "ecdsa",
			}, Signature{
				KeyId: "d4cd6865653c3aaa9b9eb865e0e45dd8ed58c98cb39c0145d500e009d9817c32",
				Sig:   "308188824201fae620e5b53e878f2b5cc9b59b8246165ecf8fb3438115dff7ecd567106c707606dceac37ffe5fa531fc03ebe310ce9397d814f1d59c78ddd975123825f976141b824201bca2b5931850d0e8453c41d8a727f136d28a7683bad34c54643978ee066a1eab3403d9dd4e82641cd6325693ee32385aa7a0b5f239f53d8b8b1174f9751e1ee114",
			}, ErrInvalidSignature,
		},
		{
			"invalid ed25519 signature", Key{
				KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				KeyIdHashAlgorithms: []string{"sha256", "sha512"},
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "",
					Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
				},
				Scheme: "ed25519",
			}, Signature{
				KeyId: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
				Sig:   "BAAAAAAD",
			}, ErrInvalidSignature,
		},
		{"invalid asn1 structure", Key{
			KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIdHashAlgorithms: []string{"sha256"},
			KeyType:             "ecdsa",
			KeyVal: KeyVal{
				Private: "",
				Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----\n",
			},
			Scheme: "ecdsa",
		}, Signature{
			KeyId: "invalid",
			Sig:   "BAAAAAAD",
		}, asn1.SyntaxError{Msg: "truncated tag or length"},
		},
		{
			"ed25519 with invalid public key", Key{
				KeyId:               "invalid",
				KeyIdHashAlgorithms: nil,
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
				KeyId:               "invalid",
				KeyIdHashAlgorithms: nil,
				KeyType:             "ed25519",
				KeyVal: KeyVal{
					Private: "",
					Public:  "",
				},
				Scheme: "ed25519",
			}, Signature{
				KeyId: "invalid",
				Sig:   "invalid",
			}, ErrInvalidHexString,
		},
		{
			name: "rsa test invalid signature",
			key: Key{
				KeyId:               "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				KeyIdHashAlgorithms: []string{"sha256"},
				KeyType:             "rsa",
				KeyVal: KeyVal{
					Private: "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
					Public:  "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l\n8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP\nr3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz\neUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT\nvpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2\nLFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5\nujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/\nVk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf\np8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=\n-----END PUBLIC KEY-----",
				},
				Scheme: "rsassa-pss-sha256",
			},
			sig: Signature{
				KeyId: "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
				Sig:   "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401",
			},
			expectedError: ErrInvalidSignature,
		},
	}
	for _, table := range invalidTables {
		err := VerifySignature(table.key, table.sig, []byte("invalid"))
		if !errors.Is(err, table.expectedError) {
			t.Errorf("test '%s' failed, should got error: '%s', but received: '%s'", table.name, table.expectedError, err)
		}
	}
}
