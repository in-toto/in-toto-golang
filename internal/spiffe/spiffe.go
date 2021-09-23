package spiffe

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// GetSVID grabs the x.509 context.
func GetSVID(ctx context.Context, socketPath string) (intoto.Key, error) {
	k := intoto.Key{}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return k, fmt.Errorf("unable to create spiffe workload API client: %w", err)
	}
	defer client.Close()

	svidContext, err := client.FetchX509Context(ctx)
	if err != nil {
		return k, fmt.Errorf("error fetching spiffe x.509 context: %w", err)
	}

	log.Printf("using svid %s\n", svidContext.DefaultSVID().ID.String())

	svid, keyBytes, err := svidContext.DefaultSVID().Marshal()
	if err != nil {
		return k, fmt.Errorf("error marshaling spiffe x.509 SVID: %w", err)
	}

	if err := k.LoadKeyReaderDefaults(bytes.NewReader(keyBytes)); err != nil {
		return k, fmt.Errorf("error loading key reader defaults: %w", err)
	}

	k.KeyVal.Certificate = string(svid)

	return k, client.Close()
}

func GetTrustBundle(ctx context.Context, socketPath string) ([]*x509.Certificate, error) {
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return nil, fmt.Errorf("unable to create spiffe workload API client: %w", err)
	}
	defer client.Close()

	bundles, err := client.FetchX509Bundles(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching spiffe x.509 bundles: %w", err)
	}

	certs := []*x509.Certificate{}
	for _, bundle := range bundles.Bundles() {
		certs = append(certs, bundle.X509Authorities()...)
	}

	return certs, client.Close()
}
