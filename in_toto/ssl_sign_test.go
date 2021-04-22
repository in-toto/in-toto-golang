package in_toto

import (
	"fmt"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ecdsa.PrivateKey{
// 	PublicKey: PublicKey{
// 		elliptic.Curve: Curve.P256(),
// 	X:46950820868899156662930047687818585632848591499744589407958293238635476079160,
// 	Y:5640078356564379163099075877009565129882514886557779369047442380624545832820
// 	}
// 	D: 97358161215184420915383655311931858321456579547487070936769975997791359926199
// }

func TestPae(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var want = make([]byte, 8)

		got, err := Pae(nil)
		assert.Nil(t, err, "Unexpectted error")
		assert.Equal(t, want, got, "Wrong encoding")
	})
	t.Run("Empty", func(t *testing.T) {
		var want = make([]byte, 8)

		got, err := Pae([][]byte{})
		assert.Nil(t, err, "Unexpectted error")
		assert.Equal(t, want, got, "Wrong encoding")
	})
	t.Run("['']", func(t *testing.T) {
		var want = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

		got, err := Pae([][]byte{[]byte("")})
		assert.Nil(t, err, "Unexpectted error")
		assert.Equal(t, want, got, "Wrong encoding")
	})
	t.Run("['test']", func(t *testing.T) {
		var want = []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74}

		got, err := Pae([][]byte{[]byte("test")})
		assert.Nil(t, err, "Unexpectted error")
		assert.Equal(t, want, got, "Wrong encoding")
	})
	t.Run("Hello world", func(t *testing.T) {
		var want = []byte{
			0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x65,
			0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63,
			0x6f, 0x6d, 0x2f, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
			0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0b, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x65, 0x6c,
			0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
		}

		got, err := Pae([][]byte{[]byte("http://example.com/HelloWorld"),
			[]byte("hello world")})
		assert.Nil(t, err, "Unexpectted error")
		assert.Equal(t, want, got, "Wrong encoding")
	})
}

type nilsigner int

func (n nilsigner) Sign(data []byte, keyID string) ([]byte, error) {
	return data, nil
}

type errsigner int

func (n errsigner) Sign(data []byte, keyID string) ([]byte, error) {
	return nil, fmt.Errorf("signing error")
}

func TestSignNoKeys(t *testing.T) {
	signer := NewEnvelopeSigner(nilsigner(0))

	t.Run("nil slice", func(t *testing.T) {
		got, err := signer.Sign("t", []byte("d"), nil)
		assert.Nil(t, got, "expected nil")
		assert.NotNil(t, err, "error expected")
		assert.Equal(t, "no keys provided", err.Error(), "wrong error")
	})

	t.Run("empty slice", func(t *testing.T) {
		got, err := signer.Sign("t", []byte("d"), []string{})
		assert.Nil(t, got, "expected nil")
		assert.NotNil(t, err, "error expected")
		assert.Equal(t, "no keys provided", err.Error(), "wrong error")
	})
}

func TestNilSign(t *testing.T) {
	var keyID = "nil"
	var payloadType = "http://example.com/HelloWorld"
	var payload = "Hello world"

	pae, err := Pae([][]byte{
		[]byte(payloadType),
		[]byte(payload),
	})
	assert.Nil(t, err, "pae failed")
	want := Envelope{
		Payload: base64.StdEncoding.EncodeToString([]byte(payload)),
		PayloadType: payloadType,
		Signatures: []Signature{
			Signature{
				KeyID: keyID,
				Sig: base64.StdEncoding.EncodeToString(pae),
			},
		},
	}

	signer := NewEnvelopeSigner(nilsigner(0))
	got, err := signer.Sign(payloadType, []byte(payload), []string{keyID})
	assert.Nil(t, err, "sign failed")
	assert.Equal(t, &want, got, "bad signature")
}

func TestSignError(t *testing.T) {
	signer := NewEnvelopeSigner(errsigner(0))
	got, err := signer.Sign("t", []byte("d"), []string{""})
	assert.Nil(t, got, "expected nil")
	assert.NotNil(t, err, "error expected")
	assert.Equal(t, "signing error", err.Error(), "wrong error")
}
