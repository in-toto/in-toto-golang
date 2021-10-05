package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var dir string

var gendoc = &cobra.Command{
	Use:          "gendoc",
	Short:        "Generate in-toto-golang's help docs",
	SilenceUsage: true,
	Args:         cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		return doc.GenMarkdownTree(rootCmd, dir)
	},
}

func init() {
	rootCmd.AddCommand(gendoc)
	gendoc.Flags().StringVarP(&dir, "dir", "d", "doc", "Path to directory in which to generate docs")
}
