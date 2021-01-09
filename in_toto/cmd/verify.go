package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify that the software supply chain of the delivered product",
	Long: `in-toto-verify is the main verification tool of the suite, and 
it is used to verify that the software supply chain of the delivered 
product was carried out as defined in the passed in-toto supply chain 
layout. Evidence for supply chain steps must be available in the form 
of link metadata files named ‘<step name>.<functionary keyid prefix>.link’.`,
	Run: func(cmd *cobra.Command, args []string) {
		var layoutMb intoto.Metablock

		if err := layoutMb.Load(layoutPath); err != nil {
			fmt.Println(err.Error())
		}

		//Load Keys
		layoutKeys := make(map[string]intoto.Key, len(pubKeyPaths))

		for _, pubKeyPath := range pubKeyPaths {
			var pubKey intoto.Key

			if err := pubKey.LoadKey(pubKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
				fmt.Println("Invalid Key Error:", err.Error())
				os.Exit(1)
			}

			layoutKeys[pubKey.KeyId] = pubKey
		}

		//Verify
		_, err := intoto.InTotoVerify(layoutMb, layoutKeys, linkDir, "", make(map[string]string))
		if err != nil {
			fmt.Println("Inspection Failed Error", err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
