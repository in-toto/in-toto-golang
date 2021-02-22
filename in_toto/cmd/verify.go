package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var layoutPath string
var pubKeyPaths []string
var linkDir string
var intermediatePaths []string

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

			layoutKeys[pubKey.KeyID] = pubKey
		}

		intermediatePems := make([][]byte, 0, len(intermediatePaths))
		for _, intermediate := range intermediatePaths {
			f, err := os.Open(intermediate)
			if err != nil {
				fmt.Println(fmt.Sprintf("failed to open %v: %v", intermediate, err))
				os.Exit(1)
			}

			pemBytes, err := ioutil.ReadAll(f)
			if err != nil {
				fmt.Println(fmt.Sprintf("failed to read %v: %v", intermediate, err))
				os.Exit(1)
			}

			intermediatePems = append(intermediatePems, pemBytes)
			if err := f.Close(); err != nil {
				fmt.Println(fmt.Sprintf("failed to read %v: %v", intermediate, err))
				os.Exit(1)
			}
		}

		//Verify
		_, err := intoto.InTotoVerify(layoutMb, layoutKeys, linkDir, "", make(map[string]string), intermediatePems)
		if err != nil {
			fmt.Println("Inspection Failed Error", err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	verifyCmd.Flags().StringVarP(&layoutPath,
		"layout", "l", "",
		`Path to root layout specifying the software supply chain to be verified`)
	verifyCmd.Flags().StringSliceVarP(&pubKeyPaths,
		"layout-keys", "k", []string{},
		`Path(s) to PEM formatted public key(s), used to verify the passed 
root layout's signature(s). Passing at least one key using
'--layout-keys' is required. For each passed key the layout
must carry a valid signature.`)
	verifyCmd.Flags().StringVarP(&linkDir,
		"link-dir", "d", "",
		`Path to directory where link metadata files for steps defined in 
the root layout should be loaded from. If not passed links are 
loaded from the current working directory.`)
	verifyCmd.Flags().StringSliceVarP(&intermediatePaths,
		"intermediate-certs", "i", []string{},
		`Path(s) to PEM formatted certificates, used as intermediaetes to verify
the chain of trust to the layout's trusted root. These will be used in
addition to any intermediates in the layout.`)
	verifyCmd.MarkFlagRequired("layout")
	verifyCmd.MarkFlagRequired("layout-keys")

}
