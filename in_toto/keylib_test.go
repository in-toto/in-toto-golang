package in_toto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseRSAPublicKeyFromPEM(t *testing.T) {
	// Test parsing errors:
	// - Missing pem headers,
	// - Missing pem body
	// - Not an rsa key
	invalidRSA := []string{
		"not a PEM block",
		`-----BEGIN PUBLIC KEY-----

-----END PUBLIC KEY-----`,
		`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESkhkURrGhKzC8IyJTP1H3QCVi4CU
z5OxbcSn3IR+/9W02DOVayQHTnMlBc1SoStYMvbGwnPraQuh6t+U/NBHYQ==
-----END PUBLIC KEY-----`,
	}
	expectedErrors := []string{
		"Could not find a public key PEM block",
		"truncated",
		"only support rsa",
	}

	for i := 0; i < len(invalidRSA); i++ {
		result, err := ParseRSAPublicKeyFromPEM([]byte(invalidRSA[i]))
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("ParseRSAPublicKeyFromPEM returned (%p, %s), expected '%s'"+
				" error", result, err, expectedErrors[i])
		}
	}

	// Test parsing valid public rsa key from PEM bytes
	validRSA := `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxPX3kFs/z645x4UOC3KF
Y3V80YQtKrp6YS3qU+Jlvx/XzK53lb4sCDRU9jqBBx3We45TmFUibroMd8tQXCUS
e8gYCBUBqBmmz0dEHJYbW0tYF7IoapMIxhRYn76YqNdl1JoRTcmzIaOJ7QrHxQrS
GpivvTm6kQ9WLeApG1GLYJ3C3Wl4bnsI1bKSv55Zi45/JawHzTzYUAIXX9qCd3Io
HzDucz9IAj9Ookw0va/q9FjoPGrRB80IReVxLVnbo6pYJfu/O37jvEobHFa8ckHd
YxUIg8wvkIOy1O3M74lBDm6CVI0ZO25xPlDB/4nHAE1PbA3aF3lw8JGuxLDsetxm
fzgAleVt4vXLQiCrZaLf+0cM97JcT7wdHcbIvRLsij9LNP+2tWZgeZ/hIAOEdaDq
cYANPDIAxfTvbe9I0sXrCtrLer1SS7GqUmdFCdkdun8erXdNF0ls9Rp4cbYhjdf3
yMxdI/24LUOOQ71cHW3ITIDImm6I8KmrXFM2NewTARKfAgMBAAE=
-----END PUBLIC KEY-----`
	result, err := ParseRSAPublicKeyFromPEM([]byte(validRSA))
	if err != nil {
		t.Errorf("ParseRSAPublicKeyFromPEM returned (%p, %s), expected no error",
			result, err)
	}
}

func TestParseRSAPrivateKeyFromPEM(t *testing.T) {
	// Test parsing errors:
	// - Missing pem headers,
	// - Missing pem body
	// We only support RSA private keys, therefore we don't need to check for other keys.
	// Other keys should fail at ParsePKCS1 stage already.
	invalidRSA := []string{
		"not a PEM block",
		`-----BEGIN PRIVATE KEY-----

-----END PRIVATE KEY-----`,
	}
	expectedErrors := []string{
		"Could not find a private key PEM block",
		"truncated",
	}

	for i := 0; i < len(invalidRSA); i++ {
		result, err := ParseRSAPrivateKeyFromPEM([]byte(invalidRSA[i]))
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("ParseRSAPrivateKeyFromPEM returned (%p, %s), expected '%s'"+
				" error", result, err, expectedErrors[i])
		}
	}
}

func TestLoadRSAPublicKey(t *testing.T) {
	// Test loading valid public rsa key from pem-formatted file
	var key Key
	err := key.LoadRSAPublicKey("alice.pub")
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
	err = key.LoadRSAPublicKey("demo.layout.template")
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Errorf("LoadRSAPublicKey returned (%s), expected '%s' error", err,
			expectedError)
	}

	// Test not existing file
	err = key.LoadRSAPublicKey("inToToRocks")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Invalid file load returned (%s), expected '%s' error", err, os.ErrNotExist)
	}
}

func TestLoadRSAPrivateKey(t *testing.T) {
	// Test loading valid Private rsa key from pem-formatted file
	var key Key
	err := key.LoadRSAPrivateKey("dan")
	if err != nil {
		t.Errorf("LoadRSAPrivateKey returned %s, expected no error", err)
	}
	expectedKeyID := "b7d643dec0a051096ee5d87221b5d91a33daa658699d30903e1cefb90c418401"
	if key.KeyId != expectedKeyID {
		t.Errorf("LoadRSAPrivateKey parsed KeyId '%s', expected '%s'",
			key.KeyId, expectedKeyID)
	}

	// Test loading error:
	// - Not a pem formatted rsa Private key
	expectedError := "Could not find a private key PEM block"
	err = key.LoadRSAPrivateKey("demo.layout.template")
	if err == nil || !strings.Contains(err.Error(), expectedError) {
		t.Errorf("LoadRSAPrivateKey returned (%s), expected '%s' error", err,
			expectedError)
	}

	// Test not existing file
	err = key.LoadRSAPrivateKey("inToToRocks")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Invalid file load returned (%s), expected '%s' error", err, os.ErrNotExist)
	}
}

func TestGenerateRSASignature(t *testing.T) {
	validKey := Key{
		KeyId: "f29cb6877d14ebcf28b136a96a4d64935522afaddcc84e6b70ff6b9eaefb8fcf",
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
	validSig, err := GenerateRSASignature([]byte(validData), validKey)
	if err != nil {
		t.Errorf("GenerateRSASignature from validKey and data failed: %s", err)
	}
	if err := VerifyRSASignature(validKey, validSig, []byte(validData)); err != nil {
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
		KeyId: "2f89b9272acfc8f4a0a0f094d789fdb0ba798b0fe41f2f5f417c12f0085ff498",
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
	err := VerifyRSASignature(validKey, validSig, []byte(validData))
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
	if err := wrongKey.LoadRSAPublicKey("alice.pub"); err != nil {
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
		err := VerifyRSASignature(keys[i], sigs[i], []byte(data[i]))
		if err == nil {
			t.Errorf("VerifyRSASignature returned '%s', expected error", err)
		}
	}
}

func TestParseEd25519FromPrivateJSON(t *testing.T) {
	// Test parsing errors:
	// - Not JSON,
	// - Missing private field
	// - private field is the wrong length
	// - scheme and keytype are not ed25519
	invalidKey := []string{
		"not a json",
		`{"keytype": "ed25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": ""}}`,
		`{"keytype": "ed25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": "861fd1b466cfc6f73"}}`,
		`{"keytype": "25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": "861fd1b466cfc6f73f8ed630f99d8eda250421f0e3a6123fd5c311cc001bda49"}}`,
		`{"keytype": "ed25519", "scheme": "cd25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": "861fd1b466cfc6f73f8ed630f99d8eda250421f0e3a6123fd5c311cc001bda49"}}`,
	}

	expectedErrors := []string{
		"this is not a valid JSON key object",
		"in key '308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64': private key cannot be empty",
		"the private field on this key is malformed",
		"this doesn't appear to be an ed25519 key",
		"this doesn't appear to be an ed25519 key",
	}

	for i := 0; i < len(invalidKey); i++ {
		_, err := ParseEd25519FromPrivateJSON(invalidKey[i])
		if err == nil || !strings.Contains(err.Error(), expectedErrors[i]) {
			t.Errorf("ParseEd25519FromPrivateJSON returned (%s), expected '%s'"+
				" error", err, expectedErrors[i])
		}
	}

	// Generated through in-toto run 0.4.1 and thus it should be a happy key
	validKey := `{"keytype": "ed25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": "861fd1b466cfc6f73f8ed630f99d8eda250421f0e3a6123fd5c311cc001bda49"}}`
	_, err := ParseEd25519FromPrivateJSON(validKey)
	if err != nil {
		t.Errorf("ParseEd25519FromPrivateJSON returned (%s), expected no error",
			err)
	}

}

func TestGenerateEd25519Signature(t *testing.T) {
	// let's load a key in memory here first
	validKey := `{"keytype": "ed25519", "scheme": "ed25519", "keyid": "308e3f53523b632983a988b72a2e39c85fe8fc967116043ce51fa8d92a6aef64", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8f93f549eb4cca8dc2142fb655ba2d0955d1824f79474f354e38d6a359e9d440", "private": "861fd1b466cfc6f73f8ed630f99d8eda250421f0e3a6123fd5c311cc001bda49"}}`
	key, err := ParseEd25519FromPrivateJSON(validKey)
	if err != nil {
		t.Errorf("ParseEd25519FromPrivateJSON returned (%s), expected no error",
			err)
	}

	signature, err := GenerateEd25519Signature([]uint8("ohmywhatatest"), key)
	if err != nil {
		t.Errorf("GenerateEd25519Signature shouldn't have returned an error (%s)",
			err)
	}

	// validate correct signature
	err = VerifyEd25519Signature(key, signature, []uint8("ohmywhatatest"))
	if err != nil {
		t.Errorf("VerifyEd25519Signature shouldn't have returned an error (%s)", err)
	}

	//validate incorrect signature
	var incorrectSig Signature
	incorrectSig.Sig = "e8912b58f47ae04a65d7437e3c82eb361f82d952"
	err = VerifyEd25519Signature(key, incorrectSig, []uint8("ohmywhatatest"))
	if err == nil {
		t.Errorf("Given signature is valid, but should be invalid")
	}

	// validate InvalidByte signature
	var malformedSig Signature
	malformedSig.Sig = "InTotoRocks"
	err = VerifyEd25519Signature(key, malformedSig, []uint8("ohmywhatatest"))
	// use type conversion for checking for hex.InvalidByteError
	var invalidByteError hex.InvalidByteError
	if !errors.As(err, &invalidByteError) {
		t.Errorf("We received %s, but we should get: invalid byte error", err)
	}

	// validate invalidLength signature
	// the following signature is too short
	var invLengthSig Signature
	invLengthSig.Sig = "e8912b58f47ae04a65d74"
	err = VerifyEd25519Signature(key, invLengthSig, []uint8("ohmywhatatest"))
	if !errors.Is(err, hex.ErrLength) {
		t.Errorf("We received %s, but we should get: %s", err, hex.ErrLength)
	}

	// validate invalidKey
	wrongKey := key
	wrongKey.KeyVal.Public = "e8912b58f47ae04a65d7437e3c82eb361f82d952b4d1b3dc5d90c6f37d7"
	err = VerifyEd25519Signature(wrongKey, signature, []uint8("ohmywhatatest"))
	if err == nil {
		t.Errorf("The invalid testKey passed the signature test, this should not happen")
	}

	if signature.KeyId != key.KeyId {
		t.Errorf("GenerateEd25519Signature should've returned matching keyids!")
	}

	// ed25519 signatures should be 64 bytes long => 128 hex digits
	if len(signature.Sig) != 128 {
		t.Errorf("GenerateEd25519Signature should've returned a 32 byte signature! %s",
			signature.Sig)
	}
}

func TestLoad25519PublicKey(t *testing.T) {
	var key Key
	if err := key.LoadEd25519PublicKey("carol.pub"); err != nil {
		t.Errorf("Failed to load ed25519 public key from file: (%s)", err)
	}

	expectedPubKey := "8c93f633f2378cc64dd7cbb0ed35eac59e1f28065f90cbbddb59878436fec037"
	if expectedPubKey != key.KeyVal.Public {
		t.Errorf("Loaded pubkey is not the expected key")
	}

	// try to load nonexistent file
	if err := key.LoadEd25519PublicKey("this-does-not-exist"); err == nil {
		t.Errorf("LoadEd25519PublicKey loaded a file that does not exist")
	}

	// load invalid file
	if err := key.LoadEd25519PublicKey("bob-invalid.pub"); err == nil {
		t.Errorf("LoadEd25519PublicKey has successfully loaded an invalid key file")
	}
}

func TestLoad25519PrivateKey(t *testing.T) {
	var key Key
	if err := key.LoadEd25519PrivateKey("carol"); err != nil {
		t.Errorf("Failed to load ed25519 public key from file: (%s)", err)
	}

	expectedPrivateKey := "4cedf4d3369f8c83af472d0d329aedaa86265b74efb74b708f6a1ed23f290162"
	if expectedPrivateKey != key.KeyVal.Private {
		t.Errorf("Loaded pubkey is not the expected key")
	}

	// try to load nonexistent file
	if err := key.LoadEd25519PrivateKey("this-does-not-exist"); err == nil {
		t.Errorf("LoadEd25519PublicKey loaded a file that does not exist")
	}

	// load invalid file
	if err := key.LoadEd25519PrivateKey("bob-invalid.pub"); err == nil {
		t.Errorf("LoadEd25519PublicKey has successfully loaded an invalid key file")
	}
}

func TestParseEd25519FromPublicJSON(t *testing.T) {
	tables := []struct {
		invalidKey    string
		expectedError string
	}{
		{"not a json", "this is not a valid JSON key object"},
		{`{"keytype": "ed25519", "scheme": "ed25519", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8c93f633f2378cc64dd7cbb0ed35eac59e1f28065f90cbbddb59878436fec037", "private": "4cedf4d3369f8c83af472d0d329aedaa86265b74efb74b708f6a1ed23f290162"}}`, "private key found"},
		{`{"keytype": "ed25519", "scheme": "ed25519", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8c93f633f2378cc64"}}`, "the public field on this key is malformed"},
		{`{"keytype": "25519", "scheme": "ed25519", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8c93f633f2378cc64dd7cbb0ed35eac59e1f28065f90cbbddb59878436fec037"}}`, "this doesn't appear to be an ed25519 key"},
		{`{"keytype": "ed25519", "scheme": "ec25519", "keyid_hash_algorithms": ["sha256", "sha512"], "keyval": {"public": "8c93f633f2378cc64dd7cbb0ed35eac59e1f28065f90cbbddb59878436fec037"}}}`, "this is not a valid JSON key object"},
	}

	for _, table := range tables {
		_, err := ParseEd25519FromPublicJSON(table.invalidKey)
		if err == nil || !strings.Contains(err.Error(), table.expectedError) {
			t.Errorf("ParseEd25519FromPublicJSON returned (%s), expected '%s'", err, table.expectedError)
		}
	}
}
