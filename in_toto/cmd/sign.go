package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

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
		block.Dump("signed.layout")

	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	signCmd.Flags().StringVarP(&layoutPath,
		"layout", "l", "",
		`Path to root layout specifying the software supply chain to be verified`)
	signCmd.Flags().StringVarP(&keyPath,
		"layout-key", "k", "",
		`Path(s) to PEM formatted private key(s) used to sign the passed 
root layout's signature(s). Passing exactly one key using
'--layout-key' is	required.`)
	signCmd.MarkFlagRequired("layout")
	signCmd.MarkFlagRequired("layout-key")

}
