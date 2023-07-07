package cmd

import (
	"fmt"
	"os"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var matchProductsCmd = &cobra.Command{
	Use:   "match-products",
	Short: "Check if local artifacts match products in passed link",
	RunE:  matchProducts,
}

var (
	linkMetadataPath string
	paths            []string
)

func init() {
	rootCmd.AddCommand(matchProductsCmd)

	matchProductsCmd.Flags().StringVarP(
		&linkMetadataPath,
		"link",
		"l",
		"",
		"Path to link metadata file",
	)
	matchProductsCmd.MarkFlagRequired("link") //nolint:errcheck

	matchProductsCmd.Flags().StringArrayVarP(
		&paths,
		"path",
		"p",
		[]string{"."},
		"file or directory paths to local artifacts, default is CWD",
	)

	matchProductsCmd.Flags().StringArrayVarP(
		&exclude,
		"exclude",
		"e",
		[]string{},
		"gitignore-style patterns to exclude artifacts from matching",
	)

	matchProductsCmd.Flags().StringArrayVar(
		&lStripPaths,
		"lstrip-paths",
		[]string{},
		`Path prefixes used to left-strip artifact paths before storing
them to the resulting link metadata. If multiple prefixes
are specified, only a single prefix can match the path of
any artifact and that is then left-stripped. All prefixes
are checked to ensure none of them are a left substring
of another.`,
	)
}

func matchProducts(cmd *cobra.Command, args []string) error {
	linkEnv, err := in_toto.LoadMetadata(linkMetadataPath)
	if err != nil {
		return err
	}

	link, ok := linkEnv.GetPayload().(in_toto.Link)
	if !ok {
		return fmt.Errorf("metadata must be link")
	}

	onlyInProducts, notInProducts, differ, err := in_toto.InTotoMatchProducts(&link, paths, []string{"sha256"}, exclude, lStripPaths)
	if err != nil {
		return err
	}

	if len(onlyInProducts) != 0 || len(notInProducts) != 0 || len(differ) != 0 {
		for _, name := range onlyInProducts {
			fmt.Printf("Only in products: %s\n", name)
		}

		for _, name := range notInProducts {
			fmt.Printf("Not in products: %s\n", name)
		}

		for _, name := range differ {
			fmt.Printf("Hashes differ: %s\n", name)
		}
		os.Exit(1)
	}

	return nil
}
