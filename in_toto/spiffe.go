package in_toto

import (
	"context"
	"log"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

//GetSVID grabs the x.509 context.
func GetSVID(socketPath string, ctx context.Context) *workloadapi.X509Context {

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	svidContext, err := client.FetchX509Context(ctx)
	if err != nil {
		log.Fatalf("Error grabbing x.509 context")
	}

	certBytes, keyBytes, err := svidContext.DefaultSVID().Marshal()

	return
}
