package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var outputPath string

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Provides command line interface to sign in-toto link or layout metadata",
	Long:  `Provides command line interface to sign in-toto link or layout metadata`,
	Run: func(cmd *cobra.Command, args []string) {

		var block intoto.Metablock

		if err := block.Load(layoutPath); err != nil {
			fmt.Println(err.Error())
		}

		//Load Keys
		var layoutKey intoto.Key

		if err := layoutKey.LoadKey(keyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			fmt.Println("Invalid Key Error:", err.Error())
			os.Exit(1)
		}

		//Sign
		block.Sign(layoutKey)
		block.Dump(outputPath)

	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&outputPath,
		"output", "o", "",
		`Path to store metadata file to be signed`)
	signCmd.Flags().StringVarP(&layoutPath,
		"file", "f", "",
		`Path to link or layout file to be signed or verified.`)
	signCmd.Flags().StringVarP(&keyPath,
		"key", "k", "",
		`Path to PEM formatted private key used to sign the passed 
root layout's signature(s). Passing exactly one key using
'--layout-key' is	required.`)

	signCmd.MarkFlagRequired("file")
	signCmd.MarkFlagRequired("key")
	signCmd.MarkFlagRequired("output")

}
