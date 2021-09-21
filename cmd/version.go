package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var (
	commit = "none"
	date   = "unknown"
	tag    = "dev"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the version of the in-toto CLI tool",
	Long:  `Display the commit ID, the build date and the version tag of the in-toto CLI as embedded by the build system.`,
	RunE:  version,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func version(cmd *cobra.Command, args []string) error {
	// let us make it as simple as possible.
	// We could encode the version information as JSON like kubectl does,
	// but what if the json package has a bug? :/
	fmt.Println("commit : ", commit)
	fmt.Println("date   : ", date)
	fmt.Println("version: ", tag)
	return nil
}
