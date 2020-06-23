package in_toto

import (
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

func TestLoadPublicKey(t *testing.T) {
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

func TestVerifySignature(t *testing.T) {
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
		"this key is not a private key",
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
		t.Errorf("GenerateEd25519Signature shouldn't have returned error (%s)",
			err)
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
