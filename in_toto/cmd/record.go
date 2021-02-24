package cmd

import (
	"fmt"
	"os"

	intoto "github.com/boxboat/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var (
	recordKeyPath        string
	recordStepName       string
	recordCertPath       string
	recordProductsPaths  []string
	recordMaterialsPaths []string
	recordKey            intoto.Key
)

var recordCmd = &cobra.Command{
	Use: "record",
	Short: `Creates a signed link metadata file in two steps, in order to provide
evidence for supply chain steps that cannot be carried out by a single command`,
	Long: `Creates a signed link metadata file in two steps, in order to provide
evidence for supply chain steps that cannot be carried out by a single command
(for which ‘in-toto-run’ should be used). It returns a non-zero value on
failure and zero otherwise.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if err := recordKey.LoadKey(recordKeyPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
			fmt.Println("Invalid Key Error:", err.Error())
			os.Exit(1)
		}

		if len(recordCertPath) > 0 {
			var cert intoto.Key
			if err := cert.LoadKey(recordCertPath, "rsassa-pss-sha256", []string{"sha256", "sha512"}); err != nil {
				fmt.Println("Invalid Certificate Error:", err.Error())
				os.Exit(1)
			}

			recordKey.KeyVal.Certificate = cert.KeyVal.Certificate
		}
	},
}

var recordStartCmd = &cobra.Command{
	Use: "start",
	Short: `Creates a preliminary link file recording the paths and hashes of the
passed materials and signs it with the passed functionary’s key.`,
	Long: `Creates a preliminary link file recording the paths and hashes of the
passed materials and signs it with the passed functionary’s key.
The resulting link file is stored as ‘.<name>.<keyid prefix>.link-unfinished’.`,
	Run: func(cmd *cobra.Command, args []string) {
		block, err := intoto.InTotoRecordStart(recordStepName, recordMaterialsPaths, recordKey, []string{"sha256"}, []string{})
		if err != nil {
			fmt.Println("Error generating meta-block:", err.Error())
			os.Exit(1)
		}

		prelimLinkName := fmt.Sprintf(intoto.PreliminaryLinkNameFormat, recordStepName, recordKey.KeyID)
		err = block.Dump(prelimLinkName)
		if err != nil {
			fmt.Println("Error writing meta-block:", err.Error())
			os.Exit(1)
		}
	},
}

var recordStopCmd = &cobra.Command{
	Use:   "stop",
	Short: `Records and adds the paths and hashes of the passed products to the link metadata file and updates the signature.`,
	Long: `Expects preliminary link file ‘.<name>.<keyid prefix>.link-unfinished’ in the CWD,
signed by the passed functionary’s key. If found, it records
and adds the paths and hashes of the passed products to the
link metadata file, updates the signature and renames the
file to ‘<name>.<keyid prefix>.link’.`,
	Run: func(cmd *cobra.Command, args []string) {
		var prelimLinkMb intoto.Metablock
		prelimLinkName := fmt.Sprintf(intoto.PreliminaryLinkNameFormat, recordStepName, recordKey.KeyID)
		if err := prelimLinkMb.Load(prelimLinkName); err != nil {
			fmt.Println("Error loading meta-block:", err.Error())
			os.Exit(1)
		}

		linkMb, err := intoto.InTotoRecordStop(prelimLinkMb, recordProductsPaths, recordKey, []string{"sha256"}, []string{})
		if err != nil {
			fmt.Println("Error generating meta-block:", err.Error())
			os.Exit(1)
		}

		linkName := fmt.Sprintf(intoto.LinkNameFormat, recordStepName, recordKey.KeyID)
		err = linkMb.Dump(linkName)
		if err != nil {
			fmt.Println("Error writing meta-block:", err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	recordCmd.AddCommand(recordStartCmd)
	recordStartCmd.Flags().StringArrayVarP(&recordMaterialsPaths,
		"materials", "m", []string{},
		`Paths to files or directories, whose paths and hashes
are stored in the resulting link metadata before the
command is executed. Symlinks are followed.`)

	recordCmd.AddCommand(recordStopCmd)
	recordStopCmd.Flags().StringArrayVarP(&recordProductsPaths,
		"products", "p", []string{},
		`Paths to files or directories, whose paths and hashes
are stored in the resulting link metadata after the
command is executed. Symlinks are followed.`)

	rootCmd.AddCommand(recordCmd)
	recordCmd.PersistentFlags().StringVarP(&recordKeyPath, "key", "k", "", `Path to a private key file to sign the resulting link metadata.
The keyid prefix is used as an infix for the link metadata filename,
i.e. ‘<name>.<keyid prefix>.link’. See ‘–key-type’ for available
formats. Passing one of ‘–key’ or ‘–gpg’ is required.`)
	recordCmd.PersistentFlags().StringVarP(&recordStepName, "name", "n", "", `name for the resulting link metadata file.
It is also used to associate the link with a step defined
in an in-toto layout.`)
	recordCmd.PersistentFlags().StringVarP(&recordCertPath, "cert", "c", "", `Path to a PEM formatted certificate that corresponds with the provided key.`)
	recordCmd.MarkPersistentFlagRequired("key")
	recordCmd.MarkPersistentFlagRequired("name")
}
