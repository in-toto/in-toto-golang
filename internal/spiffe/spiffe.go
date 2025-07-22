// Deprecated: This package has been deprecated in favor of https://github.com/in-toto/go-witness
package spiffe

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

/*
SVIDDetails captures the Private Key, Root and Intermediate Certificate
from the SVID provided by spire for the workload.
*/
type SVIDDetails struct {
	PrivateKey    crypto.Signer
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
}

/*
SVIDFetcher uses the context to connect to the spire and get the SVID associated with
the workload.
*/
type SVIDFetcher interface {
	FetchX509Context(ctx context.Context) (*workloadapi.X509Context, error)
	Close() error
}

/*
NewClient takes the context and the provided spire agent socket path in order to initialize
the workload API.
*/
func NewClient(ctx context.Context, socketPath string) (SVIDFetcher, error) {
	return workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
}

/*
GetSVID attempts to request an SVID from the provided SPIRE Workload API socket.
If attestation succeeds and an SVID is acquired the resulting X509 key &
certificate pair will be returned as well as any intermediate certificates
needed to establish trust to trust domain's root.
*/
func GetSVID(ctx context.Context, client SVIDFetcher) (SVIDDetails, error) {
	s := SVIDDetails{}
	svidContext, err := client.FetchX509Context(ctx)
	if err != nil {
		return s, fmt.Errorf("error fetching spiffe x.509 context: %w", err)
	}

	svid := svidContext.DefaultSVID()
	if len(svid.Certificates) <= 0 {
		return s, fmt.Errorf("no certificates in svid")
	}

	if svid.PrivateKey == nil {
		return s, fmt.Errorf("svid has no key")
	}

	s.PrivateKey = svid.PrivateKey
	s.Certificate = svid.Certificates[0]
	s.Intermediates = svid.Certificates[1:]
	return s, nil
}

/*
InTotoKey uses the private key and certificate obtained from Spire to initialize
intoto.key to be used for signing.
*/
func (s SVIDDetails) InTotoKey() (intoto.Key, error) {
	key := intoto.Key{}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(s.PrivateKey)
	if err != nil {
		return key, fmt.Errorf("failed to marshal svid key: %w", err)
	}

	keyPemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	err = key.LoadKeyReaderDefaults(bytes.NewReader(keyPemBytes))
	if err != nil {
		return key, fmt.Errorf("failed to load key from spire: %w", err)
	}

	key.KeyVal.Certificate = string(pem.EncodeToMemory(&pem.Block{Bytes: s.Certificate.Raw, Type: "CERTIFICATE"}))
	return key, nil
}
