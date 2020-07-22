package in_toto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestLoadRSAPublicKey(t *testing.T) {
	// Test loading valid public rsa key from pem-formatted file
	var key Key
	err := key.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"})
	if err != nil {
		t.Errorf("LoadRSAPublicKey returned %s, expected no error", err)
	}
	expectedKeyID := "556caebdc0877eed53d419b60eddb1e57fa773e4e31d70698b588f3e9cc48b35"
	if key.KeyId != expectedKeyID {
		t.Errorf("LoadRSAPublicKey parsed KeyId '%s', expected '%s'",
			key.KeyId, expectedKeyID)
	}

	// Test loading error:
	// - Not a pem formatted rsa public key
	expectedError := "Could not find a public key PEM block"
	err = key.LoadKey("demo.layout.template", "rsassa-pss-sha256", []string{"sha256", "sha512"})
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("LoadRSAPublicKey returned (%s), expected '%s' error", err,
			expectedError)
	}

	// Test not existing file
	err = key.LoadKey("inToToRocks", "rsassa-pss-sha256", []string{"sha256", "sha512"})
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Invalid file load returned (%s), expected '%s' error", err, os.ErrNotExist)
	}
}

func TestLoadRSAPrivateKey(t *testing.T) {
	// Test loading valid Private rsa key from pem-formatted file
	var key Key
	err := key.LoadKey("dan", "rsassa-pss-sha256", []string{"sha256", "sha512"})
	if err != nil {
		t.Errorf("LoadKeyKey returned %s, expected no error", err)
	}
	expectedKeyID := "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"
	if key.KeyId != expectedKeyID {
		t.Errorf("LoadKeyKey parsed KeyId '%s', expected '%s'",
			key.KeyId, expectedKeyID)
	}

	err = key.LoadKey("demo.layout.template", "", []string{})
	if err == nil || !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("LoadKey returned (%s), expected '%s' error", err,
			ErrNoPEMBlock.Error())
	}

	// Test not existing file
	err = key.LoadKey("inToToRocks", "", []string{})
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Invalid file load returned (%s), expected '%s' error", err, os.ErrNotExist)
	}
}

func TestGenerateRSASignature(t *testing.T) {
	validKey := Key{
		KeyId:   "f29cb6877d14ebcf28b136a96a4d64935522afaddcc84e6b70ff6b9eaefb8fcf",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Public: `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyCTik98953hKl6+B6n5l
8DVIDwDnvrJfpasbJ3+Rw66YcawOZinRpMxPTqWBKs7sRop7jqsQNcslUoIZLrXP
r3foPHF455TlrqPVfCZiFQ+O4CafxWOB4mL1NddvpFXTEjmUiwFrrL7PcvQKMbYz
eUHH4tH9MNzqKWbbJoekBsDpCDIxp1NbgivGBKwjRGa281sClKgpd0Q0ebl+RTcT
vpfZVDbXazQ7VqZkidt7geWq2BidOXZp/cjoXyVneKx/gYiOUv8x94svQMzSEhw2
LFMQ04A1KnGn1jxO35/fd6/OW32njyWs96RKu9UQVacYHsQfsACPWwmVqgnX/sp5
ujlvSDjyfZu7c5yUQ2asYfQPLvnjG+u7QcBukGf8hAfVgsezzX9QPiK35BKDgBU/
Vk43riJs165TJGYGVuLUhIEhHgiQtwo8pUTJS5npEe5XMDuZoighNdzoWY2nfsBf
p8348k6vJtDMB093/t6V9sTGYQcSbgKPyEQo5Pk6Wd4ZAgMBAAE=
-----END PUBLIC KEY-----`,
			Private: `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`,
		},
	}
	// We are not verifying the signature yet..
	validData := `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`
	validSig, err := GenerateSignature([]byte(validData), validKey)
	if err != nil {
		t.Errorf("GenerateRSASignature from validKey and data failed: %s", err)
	}
	if err := VerifySignature(validKey, validSig, []byte(validData)); err != nil {
		t.Errorf("VerifyRSASignature from validSignature and data has failed: %s", err)
	}
}

func TestVerifyRSASignature(t *testing.T) {
	validSig := Signature{
		KeyId: "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498",
		Sig: "a8adf1587659ca1d064b2d64debb6f03cba08a01d6d13c8b205ac7cb79ab8729159" +
			"ba6119762ac6a9a14d5ad675fd2e42ba8eb5a074ed5e8edb69fd34ad2c1b02d6d16" +
			"8c097bf4b9f063c49d23384d9002c03a3f20f307ec748baad8fb4d76ae11a96c9c9" +
			"0d9f663ddd1c0161fe22cfe528a9a5a8894806982a9e437664cfd55a56ebc8d61e9" +
			"5efa66fe5b0bc9241829629033a0f1eee382c3181731cc8f5a9687a4045af572fed" +
			"2e1835226ad00f91cc5799e325f532975190bfb685904aa81dd181421f3cfa04608" +
			"0466c060cc3400e29d4d86b8f10764f2a1af865a1ffad2cde69cb540b38c1e7e42c" +
			"fdd4a907fa1d38c99b46fcea2ddfab1b75372c1021f0c901165b6a1a8768f345641" +
			"489a23489d3b909ce0c8b774060a0ab5083df7f8026a83aa66b3668410956d8b01d" +
			"93b811d23cd276765ddbf41d54287994f5f8ff4ad4b94fcdb1e4d7ad407ee2a46c4" +
			"3f51e436b46a9670f5d05e706a6cb0d68afc0e999c2407267879291d082a30ade2a" +
			"49ea3e764c6eb1baa65f1d49b7a24bf",
	}

	validKey := Key{
		KeyId:   "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Public: `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzgLBsMFSgwBiWTBmVsyW
5KbJwLFSodAzdUhU2Bq6SdRz/W6UOBGdojZXibxupjRtAaEQW/eXDe+1CbKg6ENZ
Gt2D9HGFCQZgQS8ONgNDQGiNxgApMA0T21AaUhru0vEofzdN1DfEF4CAGv5AkcgK
salhTyONervFIjFEdXGelFZ7dVMV3Pp5WkZPG0jFQWjnmDZhUrtSxEtqbVghc3kK
AUj9Ll/3jyi2wS92Z1j5ueN8X62hWX2xBqQ6nViOMzdujkoiYCRSwuMLRqzW2CbT
L8hF1+S5KWKFzxl5sCVfpPe7V5HkgEHjwCILXTbCn2fCMKlaSbJ/MG2lW7qSY2Ro
wVXWkp1wDrsJ6Ii9f2dErv9vJeOVZeO9DsooQ5EuzLCfQLEU5mn7ul7bU7rFsb8J
xYOeudkNBatnNCgVMAkmDPiNA7E33bmL5ARRwU0iZicsqLQR32pmwdap8PjofxqQ
k7Gtvz/iYzaLrZv33cFWWTsEOqK1gKqigSqgW9T26wO9AgMBAAE=
-----END PUBLIC KEY-----`,
		},
	}
	validData := `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`

	// Test verifying valid signature
	err := VerifySignature(validKey, validSig, []byte(validData))
	if err != nil {
		t.Errorf("VerifyRSASignature returned '%s', expected nil", err)
	}

	// Test signature verification errors:
	// - Right signature and key, but wrong data
	// - Right signature and data, but wrong key
	// - Right signature and data, but invalid key
	// - Right key and data, but wrong signature
	// - Right key and data, but invalid signature
	var wrongKey Key
	if err := wrongKey.LoadKey("alice.pub", "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
		fmt.Printf("Unable to load key alice.pub: %s", err)
	}
	wrongSig := Signature{
		KeyId: validSig.KeyId,
		Sig:   "b" + validSig.Sig[1:],
	}

	sigs := []Signature{validSig, validSig, validSig, wrongSig, {}}
	keys := []Key{validKey, wrongKey, {}, validKey, validKey}
	data := []string{"bad data", validData, validData, validData, validData}

	for i := 0; i < len(sigs); i++ {
		err := VerifySignature(keys[i], sigs[i], []byte(data[i]))
		if err == nil {
			t.Errorf("VerifyRSASignature returned '%s', expected error", err)
		}
	}

	// pem.Decode errors
	invalidKey := Key{
		KeyId:               "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498",
		KeyIdHashAlgorithms: []string{"sha256", "sha512"},
		KeyType:             "rsa",
		KeyVal: KeyVal{
			Public: "INVALID",
		},
		Scheme: "rsassa-pss-sha256",
	}
	// just trigger pem.Decode function
	err = VerifySignature(invalidKey, Signature{}, []byte{})
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("VerifySignature returned '%s', should got '%s'", err, ErrNoPEMBlock)
	}

	// Test ParseKey errors via providing an EC key, but with wrong key type
	invalidECKey := Key{
		KeyId:   "",
		KeyType: "rsa",
		KeyVal: KeyVal{
			Public: "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
		},
	}
	// just trigger ParseKey function
	err = VerifySignature(invalidECKey, Signature{}, []byte{})
	if !errors.Is(err, ErrFailedPEMParsing) {
		t.Errorf("VerifySignature returned '%s', should got '%s'", err, ErrFailedPEMParsing)
	}
}

func TestLoadEd25519PublicKey(t *testing.T) {
	var key Key
	if err := key.LoadKey("carol.pub", "ed25519", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("Failed to load ed25519 public key from file: (%s)", err)
	}

	expectedPubKey := "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6"
	if expectedPubKey != key.KeyId {
		t.Errorf("Loaded pubkey is not the expected key")
	}

	// try to load nonexistent file
	if err := key.LoadKey("this-does-not-exist", "ed25519", []string{"sha256", "sha512"}); err == nil {
		t.Errorf("LoadEd25519PublicKey loaded a file that does not exist")
	}

	// load invalid file
	if err := key.LoadKey("bob-invalid.pub", "ed25519", []string{"sha256", "sha512"}); err == nil {
		t.Errorf("LoadEd25519PublicKey has successfully loaded an invalid key file")
	}
}

func TestLoadEd25519PrivateKey(t *testing.T) {
	var key Key
	if err := key.LoadKey("carol", "ed25519", []string{"sha256", "sha512"}); err != nil {
		t.Errorf("Failed to load ed25519 public key from file: (%s)", err)
	}

	expectedPrivateKey := "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6"
	if expectedPrivateKey != key.KeyId {
		t.Errorf("Loaded pubkey is not the expected key")
	}

	// try to load nonexistent file
	if err := key.LoadKey("this-does-not-exist", "ed25519", []string{"sha256", "sha512"}); err == nil {
		t.Errorf("LoadEd25519PublicKey loaded a file that does not exist")
	}

	// load invalid file
	if err := key.LoadKey("bob-invalid.pub", "ed25519", []string{"sha256", "sha512"}); err == nil {
		t.Errorf("LoadEd25519PublicKey has successfully loaded an invalid key file")
	}
}

func TestGenerateEd25519Signature(t *testing.T) {
	validKey := Key{
		KeyId:   "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
		KeyType: "ed25519",
		KeyVal: KeyVal{
			Public:  "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
			Private: "29ad59693fe94c9d623afbb66554b4f6bb248c47761689ada4875ebda94840ae393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
		},
	}
	// We are not verifying the signature yet..
	validData := `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`
	validSig, err := GenerateSignature([]byte(validData), validKey)
	if err != nil {
		t.Errorf("GenerateEd25519Signature from validKey and data failed: %s", err)
	}
	if err := VerifySignature(validKey, validSig, []byte(validData)); err != nil {
		t.Errorf("VerifyEd25519Signature from validSignature and data has failed: %s", err)
	}
}

func TestVerifyEd25519Signature(t *testing.T) {
	validSig := Signature{
		KeyId: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
		Sig:   "f41d704809c0ae2356e1beaaf3432f4abfaaa4a26c043087d9eb6dc12b4a3c5df73f8c47a4e969e815a5d2c9853d7eba208b48c7459f6b865cd0b51a94e6d704",
	}

	validKey := Key{
		KeyId:   "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
		KeyType: "ed25519",
		KeyVal: KeyVal{
			Public: "393e671b200f964c49083d34a867f5d989ec1c69df7b66758fe471c8591b139c",
		},
	}
	validData := `{"_type":"link","byproducts":{},"command":[],"environment":{},"materials":{},"name":"foo","products":{}}`

	// Test verifying valid signature
	err := VerifySignature(validKey, validSig, []byte(validData))
	if err != nil {
		t.Errorf("VerifyEd25519Signature returned '%s', expected nil", err)
	}

	invalidSig := Signature{
		KeyId: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
		Sig:   "f41d704809c0ae2356e1beaaf3432f4abfaa",
	}

	invalidKey := Key{
		KeyId:   "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
		KeyType: "ed25519",
		KeyVal: KeyVal{
			Public: "INVALID",
		},
	}

	invalidHexSig := Signature{
		KeyId: "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
		Sig:   "INVALID",
	}

	err = VerifySignature(validKey, invalidSig, []byte(validData))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("VerifyEd25519Signature returned '%s', expected '%s'", err, ErrInvalidSignature)
	}

	err = VerifySignature(invalidKey, validSig, []byte(validData))
	var hexError hex.InvalidByteError
	if !errors.As(err, &hexError) {
		t.Errorf("VerifyEd25519Signature returned '%s', expected '%s'", err, hexError)
	}

	err = VerifySignature(validKey, invalidHexSig, []byte(validData))
	if !errors.As(err, &hexError) {
		t.Errorf("VerifyEd25519Signature returned '%s', expected '%s'", err, hexError)
	}
}

func TestInvalidKeyComponent(t *testing.T) {
	// The following is an invalid SetKeyComponents call
	var key Key
	err := key.SetKeyComponents([]byte{}, []byte{}, "inToTo", "scheme", []string{"md5", "yolo"})
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Errorf("TestInvalidKeyComponent failed. We got: %s, we should have got: %s", err, ErrUnsupportedKeyType)
	}
}

func TestInvalidPEMKey(t *testing.T) {
	_, err := ParseKey([]byte{})
	if !errors.Is(err, ErrFailedPEMParsing) {
		t.Errorf("TestInvalidPEMKey failed with zero byte data as test key. We got: %s, we should have got: %s", err, ErrFailedPEMParsing)
	}
}

func TestLoadKey(t *testing.T) {
	tables := []struct {
		name                string
		path                string
		scheme              string
		keyIdHashAlgorithms []string
		result              string
	}{
		{"Test non existing path", "this/path/is/invalid.txt", "ed25519", []string{"sha256", "sha512"}, "open this/path/is/invalid.txt: no such file or directory"},
		{"Test invalid file", "canonical-test.link", "ecdsa", []string{"sha256", "sha512"}, "failed to decode the data as PEM block (are you sure this is a pem file?)"},
		{"Test unsupported EC private key", "erin", "ecdsa", []string{"sha256", "sha512"}, "failed parsing the PEM block: unsupported PEM type"},
		{"Test unsupported PKCS8 EC key", "frank", "ecdsa", []string{"sha256", "sha512"}, "unsupported key type: *ecdsa.PrivateKey"},
	}

	for _, table := range tables {
		// initialize empty key object
		var key Key
		err := key.LoadKey(table.path, table.scheme, table.keyIdHashAlgorithms)
		// NOTE: some errors do not support errors.Is() yet, therefore we need to compare the error strings here
		// This can lead to nil pointer dereference
		if err.Error() != table.result {
			t.Errorf("%s: Loadkey('%s', '%s', '%s') failed with '%s', should got '%s'", table.name, table.path, table.scheme, table.keyIdHashAlgorithms, err, table.result)
		}
	}
}

func TestGenerateKey(t *testing.T) {
	tables := []struct {
		name     string
		signable []byte
		key      Key
		result   string
	}{
		{"Test unsupported EC private key", []byte{}, Key{
			KeyId:               "",
			KeyIdHashAlgorithms: []string{"sha256", "sha512"},
			KeyType:             "ecdsa",
			KeyVal: KeyVal{
				Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----\n",
				Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
			},
			Scheme: "ecdsa",
		}, "unsupported key type: ecdsa"},
		{"Test wrong KeyType", []byte{}, Key{
			KeyId:               "",
			KeyIdHashAlgorithms: []string{"sha256", "sha512"},
			KeyType:             "rsa",
			KeyVal: KeyVal{
				Private: "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIJ+y3Jy7kstRBzPmoOfak4t70DsLpFmlZLtppfcP14V3oAcGBSuBBAAK\noUQDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMTOZkriRklJ4HXQbJUWRpv2X8k\nspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END EC PRIVATE KEY-----\n",
				Public:  "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAELToC9CwqXL8bRTG54QMn3k6dqwI0sDMT\nOZkriRklJ4HXQbJUWRpv2X8kspRECJZDoiOV1OaMMIXjY4XNeoEBmw==\n-----END PUBLIC KEY-----\n",
			},
			Scheme: "ecdsa",
		}, "failed parsing the PEM block: unsupported PEM type"},
		{"Test wrong KeyType, but valid PKCS8 key", []byte{}, Key{
			KeyId:               "",
			KeyIdHashAlgorithms: []string{"sha256", "sha512"},
			KeyType:             "rsa",
			KeyVal: KeyVal{
				Private: "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB6fQnV71xKx6kFgJv\nYTMq0ytvWi2mDlYu6aNm1761c1OSInbBxBNb0ligpM65KyaeeRce6JR9eQW6TB6R\n+5pNzvOhgYkDgYYABAFy0CeDAyV/2mY1NqxLLgqEXSxaqM3fM8gYn/ZWzrLnO+1h\nK2QAanID3JuPff1NdhehhL/U1prXdyyaItA5X4ChkQHMTsiS/3HkWRuLR8L22SGs\nB+7KqOeO5ELkqHO5tsy4kvsNrmersCGRQGY6A5V/0JFhP1u1JUvAVVhfRbdQXuu3\nrw==\n-----END PRIVATE KEY-----\n",
				Public:  "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBctAngwMlf9pmNTasSy4KhF0sWqjN\n3zPIGJ/2Vs6y5zvtYStkAGpyA9ybj339TXYXoYS/1Naa13csmiLQOV+AoZEBzE7I\nkv9x5Fkbi0fC9tkhrAfuyqjnjuRC5KhzubbMuJL7Da5nq7AhkUBmOgOVf9CRYT9b\ntSVLwFVYX0W3UF7rt68=\n-----END PUBLIC KEY-----",
			},
		}, "unsupported key type: *ecdsa.PrivateKey"},
		{"Test invalid hex string for ed25519", []byte{}, Key{
			KeyId:               "be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6",
			KeyIdHashAlgorithms: []string{"sha256", "sha512"},
			KeyType:             "ed25519",
			KeyVal: KeyVal{
				Private: "INVALID",
				Public:  "INVALID",
			},
			Scheme: "ed25519",
		}, "encoding/hex: invalid byte: U+0049 'I'"},
	}

	for _, table := range tables {
		_, err := GenerateSignature(table.signable, table.key)
		// Note: Some of our errors do not yet support Go 1.13 error handling
		// Thus we need to compare strings :(, this can lead to a nil pointer
		// dereference. If you encounter a nil pointer dereference, expect that
		// the GenerateSignature() func failed.
		if err.Error() != table.result {
			t.Errorf("%s: GenerateKey failed with '%s', should got '%s'", table.name, table.result, err)
		}
	}
}
