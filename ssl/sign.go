package ssl

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// ErrUnknownKey indicates that the implementation does not recognize the
// key.
var ErrUnknownKey = fmt.Errorf("unknown key")
// ErrNoSignature indicates that an envelope did not contain any signatures.
var ErrNoSignature = fmt.Errorf("no signature found")
/*
Envelope captures an envelope as described by the Secure Systems Lab
Signing Specification. See here:
 https://github.com/secure-systems-lab/signing-spec/blob/master/envelope.md
*/
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

/*
Signature represents a generic in-toto signature that contains the identifier
of the Key, which was used to create the signature and the signature data.  The
used signature scheme is found in the corresponding Key.
*/
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Pae implementes PASETO Pre-Authentic Encoding
// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
func Pae(data [][]byte) ([]byte, error) {
	var buf = bytes.Buffer{}
	var l = len(data)
	var err error

	// Negative values sets highest bit two 1 with 2 complements encoding
	// high bit must be 0 for interoperability with languages that lacks
	//  unisnged integer types.
	if l < 0 || l > 2^63 {
		return nil, fmt.Errorf("length must be less than 2^63")
	}
	if err = binary.Write(&buf, binary.LittleEndian, uint64(l)); err != nil {
		return nil, err
	}

	for _, b := range data {
		var bw int
		l = len(b)

		if l < 0 || l > 2^63 {
			return nil, fmt.Errorf("length must be less than 2^63")
		}
		if err = binary.Write(&buf, binary.LittleEndian, uint64(l)); err != nil {
			return nil, err
		}
		if bw, err = buf.Write(b); err != nil {
			return nil, err
		}
		if bw != l {
			return nil, fmt.Errorf("failed to write all bytes")
		}
	}

	return buf.Bytes(), nil
}

// Signer is an abstract signing algorithm.
// The full message is provided as the parameter. Any hashing or similar
// must not be performed by the caller, it is the signer implementor's
// responsibility.
// The returned Signature shall contain the base64 encoding of the
// binary signature and the Key id used (if applicable).
type Signer interface {
	Sign(data []byte) ([]byte, string, error)
}

// Verifier verifies a complete message against a signature and key.
// If the key is not recognized ErrUnknownKey shall be returned.
type Verifier interface {
	Verify(keyID string, data, sig []byte) (bool, error)
}

type SignVerifier interface{
	Signer
	Verifier
}

// EnvelopeSigner creates signed Envelopes.
type EnvelopeSigner struct {
	providers []SignVerifier
}

// NewEnvelopeSigner creates an EnvelopeSigner that uses 1+ Signer
// algorithms to sign the data.
func NewEnvelopeSigner(p ...SignVerifier) (*EnvelopeSigner, error) {
	var providers []SignVerifier

	for _, sv := range p {
		if sv != nil {
			providers = append(providers, sv)
		}
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no signers provided")
	}

	return &EnvelopeSigner{
		providers: providers,
	}, nil
}

// Sign signs a payload and payload type according to the SSL signing spec.
// One signature will be added for each Signer in the EnvelopeSigner.
func (es *EnvelopeSigner) Sign(payloadType string, body []byte) (*Envelope, error) {
	var paeEnc []byte
	var err error
	var e = Envelope{
		Payload:     base64.StdEncoding.EncodeToString(body),
		PayloadType: payloadType,
	}

	paeEnc, err = Pae([][]byte{
		[]byte(payloadType),
		body,
	})
	if err != nil {
		return nil, err
	}

	for _, signer := range es.providers {
		var sig []byte
		var keyID string

		sig, keyID, err = signer.Sign(paeEnc)
		if err != nil {
			return nil, err
		}

		e.Signatures = append(e.Signatures, Signature{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		})
	}

	return &e, nil
}

// Verify decodes the payload and verifies the signature.
// Any domain specific validation such as parsing the decoded body and
// validating the payload type is left out to the caller.
func (es *EnvelopeSigner) Verify(e *Envelope) (bool, error) {
	if len(e.Signatures) == 0{
		return false, ErrNoSignature
	}

	// Decode payload (i.e serialized body)
	body, err := b64Decode(e.Payload)
	if err != nil {
		return false, err
	}
	// Generate PAE(payloadtype, serialized body)
	paeEnc, err := Pae([][]byte{
		[]byte(e.PayloadType),
		body,
	})

	verified := false
	for _, s := range e.Signatures{
		sig, err := b64Decode(s.Sig)
		if err != nil {
			return false, err
		}

		// Loop over each providers. If we find a provider that recognizes
		// the key, the value is used as the result. No more providers will
		// be called.
		for _, v := range es.providers {
			ok, err := v.Verify(s.KeyID, paeEnc, sig)
			if err != nil {
				if err == ErrUnknownKey {
					continue
				}
				return false, err
			}

			if !ok {
				return false, nil
			}
			verified = true
			break
		}
	}

	return verified, nil
}

// Both standard and url encoding are allowed:
// https://github.com/secure-systems-lab/signing-spec/blob/master/envelope.md
func b64Decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}

	return b, nil
}