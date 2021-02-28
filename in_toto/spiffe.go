package in_toto

import (
	"context"
	"log"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

//GetSVID grabs the x.509 context.
func GetSVID(ctx context.Context, socketPath string) Key {

	var k Key

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	svidContext, err := client.FetchX509Context(ctx)
	if err != nil {
		log.Fatalf("Error grabbing x.509 context: %v", err)
	}

	_, keyBytes, err := svidContext.DefaultSVID().Marshal()
	if err != nil {
		log.Fatalf("Error marshaling certificate: %v", err)
	}
	svidContext.DefaultSVID().ID.Path()

	pemData, key, err := decodeAndParse(keyBytes)

	if err != nil {
		log.Fatalf("Error decoding: %v", err)
	}

	k.loadKey(key, pemData, "rsassa-pss-sha256", []string{"sha256", "sha512"})
	return k
}
