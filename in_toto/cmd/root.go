package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "in-toto",
	Short: "Framework to secure integrity of software supply chains",
	Long:  `A framework to secure the integrity of software supply chains https://in-toto.io/`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var layoutPath string
var pubKeyPaths []string
var linkDir string

func init() {
	rootCmd.PersistentFlags().StringVarP(&layoutPath,
		"layout", "l", "",
		`Path to root layout specifying the software supply chain to be 
		verified`)
	rootCmd.PersistentFlags().StringSliceVar(&pubKeyPaths,
		"layout-keys", []string{},
		`Path(s) to PEM formatted public key(s), used to verify the passed 
	 	root layout's signature(s). Passing at	least one key using
	 	'--layout-keys' is	required. For each passed key the layout 
	 	must carry a valid signature.`)
	rootCmd.PersistentFlags().StringVarP(&linkDir,
		"link-dir", "d", "",
		`Path to directory where link metadata files for steps defined in 
		the root layout should be loaded from. If not passed links are 
		loaded from the current working	directory.`)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
