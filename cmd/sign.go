package cmd

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var (
	outputPath string
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Provides command line interface to sign in-toto link or layout metadata",
	Long:  `Provides command line interface to sign in-toto link or layout metadata`,
	RunE:  sign,
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(
		&outputPath,
		"output",
		"o",
		"",
		`Path to store metadata file to be signed`,
	)

	signCmd.Flags().StringVarP(
		&layoutPath,
		"file",
		"f",
		"",
		`Path to link or layout file to be signed or verified.`,
	)

	signCmd.Flags().StringVarP(
		&keyPath,
		"key",
		"k",
		"",
		`Path to PEM formatted private key used to sign the passed 
root layout's signature(s). Passing exactly one key using
'--key' is required.`,
	)

	signCmd.MarkFlagRequired("file")
	signCmd.MarkFlagRequired("key")
	signCmd.MarkFlagRequired("output")
}

func sign(cmd *cobra.Command, args []string) error {
	var layoutMb intoto.Metablock

	if err := layoutMb.Load(layoutPath); err != nil {
		return fmt.Errorf("failed to load layout at %s: %w", layoutPath, err)
	}

	key = intoto.Key{}
	if err := key.LoadKeyDefaults(keyPath); err != nil {
		return fmt.Errorf("invalid key at %s: %w", keyPath, err)
	}

	layoutMb.Sign(key)
	layoutMb.Dump(outputPath)

	return nil
}
