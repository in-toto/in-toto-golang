package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "in-toto",
	Short: "Framework to secure integrity of software supply chains",
	Long:  `A framework to secure the integrity of software supply chains https://in-toto.io/`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(pubKeyPath)
		var layoutMb intoto.Metablock
		if err := layoutMb.Load(layoutPath); err != nil {
			fmt.Println(err.Error())
		}

		var pubKey intoto.Key
		if err := pubKey.LoadKey(pubKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			fmt.Println(err.Error())
		}

		var layoutKeys = map[string]intoto.Key{
			pubKey.KeyId: pubKey,
		}

		result, err := intoto.InTotoVerify(layoutMb, layoutKeys, linkDir, "", make(map[string]string))
		if err != nil {
			fmt.Println(err.Error())
		}

		resultjson, err := result.GetSignableRepresentation()
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(resultjson)
	},
}

var layoutPath string
var pubKeyPath string
var linkDir string

func init() {
	rootCmd.PersistentFlags().StringVar(&layoutPath, "layout-path", "", "Full Path For Layout")
	rootCmd.PersistentFlags().StringVar(&pubKeyPath, "pubkey-path", "", "Full Path For Public Key")
	rootCmd.PersistentFlags().StringVar(&linkDir, "link-metadata", "", "Link metadata directory")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
