/*
Package ssl implements the Secure Systems Lab signing-spec (sometimes
abbreviated SSL Siging spec.
https://github.com/secure-systems-lab/signing-spec
*/
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
of the key which was used to create the signature.
The used signature scheme has to be agreed upon by the signer and verifer
out of band.
The signature is a base64 encoding of the raw bytes from the signature
algorithm.
*/
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

/*
Pae implementes PASETO Pre-Authentic Encoding
https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
*/
func Pae(data [][]byte) ([]byte, error) {
	var buf = bytes.Buffer{}
	var l = len(data)
	var err error

	// Negative value sets the highest bit to 1.
	// With two complements encoding, high bit must be set to 0 for
	// interoperability with languages that lack unsigned integer types.
	if !verifyPaeLength(int64(l)) {
		return nil, fmt.Errorf("length must be less than 2^63")
	}
	if err = binary.Write(&buf, binary.LittleEndian, uint64(l)); err != nil {
		return nil, err
	}

	for _, b := range data {
		var bw int
		l = len(b)

		if !verifyPaeLength(int64(l)) {
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

func verifyPaeLength(l int64) bool {
	// l is signed, so max value it can take is 2^63 - 1, which have
	// highest bit set to 0. Test only for negative values.
	if l < 0 {
		return false
	}

	return true
}

/*
Signer defines the interface for an abstract signing algorithm.
The Signer interface is used to inject signature algorithm implementations
into the EnevelopeSigner. This decoupling allows for any signing algorithm
and key management system can be used.
The full message is provided as the parameter. If the signature algorithm
depends on hashing of the message prior to signature calculation, the
implementor of this interface must perform such hashing.
The function must return raw bytes representing the calculated signature
using the current algorithm, and the key used (if applicable).
For an example see EcdsaSigner in sign_test.go.
*/
type Signer interface {
	Sign(data []byte) ([]byte, string, error)
}

/*
Verifier verifies a complete message against a signature and key.
If the message was hashed prior to signature generation, the verifier
must perform the same steps.
If the key is not recognized ErrUnknownKey shall be returned.
*/
type Verifier interface {
	Verify(keyID string, data, sig []byte) (bool, error)
}

// SignVerifer provides both the signing and verification interface.
type SignVerifier interface {
	Signer
	Verifier
}

// EnvelopeSigner creates signed Envelopes.
type EnvelopeSigner struct {
	providers []SignVerifier
}

/*
NewEnvelopeSigner creates an EnvelopeSigner that uses 1+ Signer
algorithms to sign the data.
*/
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

/*
SignPayload signs a payload and payload type according to the SSL signing spec.
Returned is an envelope as defined here:
https://github.com/secure-systems-lab/signing-spec/blob/master/envelope.md
One signature will be added for each Signer in the EnvelopeSigner.
*/
func (es *EnvelopeSigner) SignPayload(payloadType string, body []byte) (*Envelope, error) {
	var e = Envelope{
		Payload:     base64.StdEncoding.EncodeToString(body),
		PayloadType: payloadType,
	}

	paeEnc, err := Pae([][]byte{
		[]byte(payloadType),
		body,
	})
	if err != nil {
		return nil, err
	}

	for _, signer := range es.providers {
		sig, keyID, err := signer.Sign(paeEnc)
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

/*
Verify decodes the payload and verifies the signature.
Any domain specific validation such as parsing the decoded body and
validating the payload type is left out to the caller.
*/
func (es *EnvelopeSigner) Verify(e *Envelope) (bool, error) {
	if len(e.Signatures) == 0 {
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
	if err != nil {
		return false, err
	}

	// If *any* signature is found to be incorrect, the entire verification
	// step fails even if *some* signatures are correct.
	verified := false
	for _, s := range e.Signatures {
		sig, err := b64Decode(s.Sig)
		if err != nil {
			return false, err
		}

		// Loop over the providers. If a provider recognizes the key, we exit
		// the loop and use the result.
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

/*
Both standard and url encoding are allowed:
https://github.com/secure-systems-lab/signing-spec/blob/master/envelope.md
*/
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
