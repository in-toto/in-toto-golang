package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var spiffeUDS string

var rootCmd = &cobra.Command{
	Use:   "in-toto",
	Short: "Framework to secure integrity of software supply chains",
	Long:  `A framework to secure the integrity of software supply chains https://in-toto.io/`,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&spiffeUDS, "spiffe-workload-api-path", "", "uds path for spiffe workload api")
}

//Execute root
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
