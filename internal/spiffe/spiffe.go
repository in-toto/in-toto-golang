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

type SVIDDetails struct {
	PrivateKey    crypto.Signer
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate
}

type SVIDFetcher interface {
	FetchX509Context(ctx context.Context) (*workloadapi.X509Context, error)
	Close() error
}

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

func (s SVIDDetails) IntotoKey() (intoto.Key, error) {
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
