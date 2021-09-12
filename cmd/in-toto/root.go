package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/internal/spiffe"
	"github.com/spf13/cobra"
)

var (
	spiffeUDS   string
	layoutPath  string
	keyPath     string
	certPath    string
	key         intoto.Key
	cert        intoto.Key
	lStripPaths []string
	exclude     []string
	outDir      string
)

var rootCmd = &cobra.Command{
	Use:           "in-toto",
	Short:         "Framework to secure integrity of software supply chains",
	Long:          `A framework to secure the integrity of software supply chains https://in-toto.io/`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func loadKeyFromSpireSocket() error {
	ctx := context.Background()
	var err error
	spireClient, err := spiffe.NewClient(ctx, spiffeUDS)
	if err != nil {
		return fmt.Errorf("failed to create spire client: %w", err)
	}

	svidDetails, err := spiffe.GetSVID(ctx, spireClient)
	if err != nil {
		return fmt.Errorf("failed to get spiffe x.509 SVID: %w", err)
	}

	key, err = svidDetails.IntotoKey()
	if err != nil {
		return fmt.Errorf("failed to convert svid to in-toto key: %w", err)
	}

	// Write out any intermediates necessary to build the trust back
	// to the root for use during verification.
	for i, c := range svidDetails.Intermediates {
		certFileName := fmt.Sprintf("%v-intermediate-%v.cert.pem", stepName, i)
		certFile := filepath.Join(outDir, certFileName)
		certOut, err := os.Create(certFile)
		if err != nil {
			return fmt.Errorf("failed to write spiffe intermediate cert to %s: %w", certFile, err)
		}

		defer certOut.Close()
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return fmt.Errorf("failed to encode spiffe intermediate cert: %w", err)
		}
	}

	return nil
}

func loadKeyFromDisk() error {
	key = intoto.Key{}
	cert = intoto.Key{}

	if keyPath == "" && certPath == "" {
		return fmt.Errorf("key or cert must be provided")
	}

	if len(keyPath) > 0 {
		if _, err := os.Stat(keyPath); err == nil {
			if err := key.LoadKeyDefaults(keyPath); err != nil {
				return fmt.Errorf("invalid key at %s: %w", keyPath, err)
			}
		} else {
			return fmt.Errorf("key not found at %s: %w", keyPath, err)
		}
	}

	if len(certPath) > 0 {
		if _, err := os.Stat(certPath); err == nil {
			if err := cert.LoadKeyDefaults(certPath); err != nil {
				return fmt.Errorf("invalid cert at %s: %w", certPath, err)
			}
			key.KeyVal.Certificate = cert.KeyVal.Certificate
		} else {
			return fmt.Errorf("cert not found at %s: %w", certPath, err)
		}
	}
	return nil

}

func getKeyCert(cmd *cobra.Command, args []string) error {
	if spiffeUDS != "" {
		return loadKeyFromSpireSocket()
	}
	return loadKeyFromDisk()
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
