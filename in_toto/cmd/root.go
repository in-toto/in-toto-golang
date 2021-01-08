package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "hugo",
	Short: "Hugo is a very fast static site generator",
	Long: `A Fast and Flexible Static Site Generator built with
				  love by spf13 and friends in Go.
				  Complete documentation is available at http://hugo.spf13.com`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

func Execute() {
	layoutPath := "/home/nkennedy/proj/in-toto-golang/test/data/demo.layout"
	pubKeyPath := "/home/nkennedy/proj/in-toto-golang/test/data/alice.pub"
	linkDir := "/home/nkennedy/proj/in-toto-golang/test/data/."

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

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
