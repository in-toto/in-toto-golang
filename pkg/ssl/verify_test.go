package ssl

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockVerifier struct {
	returnErr error
}

func (m *mockVerifier) Verify(keyID string, data, sig []byte) (bool, error) {
	if m.returnErr != nil {
		return false, m.returnErr
	}
	return true, nil
}

// Test against the example in the protocol specification:
// https://github.com/secure-systems-lab/signing-spec/blob/master/protocol.md
func TestVerify(t *testing.T) {
	var keyID = "test key 123"
	var payloadType = "http://example.com/HelloWorld"

	e := Envelope{
		Payload:     "aGVsbG8gd29ybGQ=",
		PayloadType: payloadType,
		Signatures: []Signature{
			Signature{
				KeyID: keyID,
				Sig:   "Cc3RkvYsLhlaFVd+d6FPx4ZClhqW4ZT0rnCYAfv6/ckoGdwT7g/blWNpOBuL/tZhRiVFaglOGTU8GEjm4aEaNA==",
			},
		},
	}

	ev := NewEnvelopeVerifier(&mockVerifier{})
	ok, err := ev.Verify(&e)

	// Now verify
	assert.True(t, ok, "verify failed")
	assert.Nil(t, err, "unexpected error")

	// Now try an error
	ev = NewEnvelopeVerifier(&mockVerifier{returnErr: errors.New("uh oh")})
	ok, err = ev.Verify(&e)

	// Now verify
	assert.False(t, ok, "verify succeeded incorrectly")
	assert.Error(t, err)
}
