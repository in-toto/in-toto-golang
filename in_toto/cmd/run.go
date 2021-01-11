package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Executes the passed command and records paths and hashes of 'materials'",
	Long: `Executes the passed command and records paths and hashes of 'materials' (i.e.
files before command execution) and 'products' (i.e. files after command
execution) and stores them together with other information (executed command,
return value, stdout, stderr, ...) to a link metadata file, which is signed
with the passed key.  Returns nonzero value on failure and zero otherwise.`,
	Args: cobra.MinimumNArgs(1),
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
	rootCmd.AddCommand(runCmd)
}
