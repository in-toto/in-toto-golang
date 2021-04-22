package in_toto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// Temporary added until PR#100 in in-toto-golang is merged
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
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
	if l < 0  || l > 2^63 {
		return nil, fmt.Errorf("length must be less than 2^63")
	}
	if err = binary.Write(&buf, binary.LittleEndian, uint64(l)); err != nil {
		return nil, err
	}

	for _, b := range data {
		var bw int
		l = len(b)

		if l < 0  || l > 2^63 {
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

type ByteSigner interface {
	Sign(data []byte, keyID string) ([]byte, error)
}

type EnvelopeSigner struct {
	signer ByteSigner
}

func NewEnvelopeSigner(s ByteSigner) *EnvelopeSigner {
	return &EnvelopeSigner{
		signer: s,
	}
}

func (es *EnvelopeSigner) Sign(payloadType string, body []byte, keyIDs []string) (*Envelope, error) {
	var e = Envelope{
		Payload: base64.StdEncoding.EncodeToString(body),
		PayloadType: payloadType,
	}

	if len(keyIDs) == 0 {
		return nil, fmt.Errorf("no keys provided")
	}

	for _, key := range keyIDs {
		var sig []byte
		var enc []byte
		var err error

		enc, err = Pae([][]byte{
			[]byte(payloadType),
			body,
		})
		if err != nil {
			return nil, err
		}

		sig, err = es.signer.Sign(enc, key)
		if err != nil {
			return nil, err
		}

		e.Signatures = append(e.Signatures, Signature{
			KeyID: key,
			Sig: base64.StdEncoding.EncodeToString(sig),
		})
	}

	return &e, nil
}
