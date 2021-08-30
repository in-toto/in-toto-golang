package main

import (
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var (
	recordStepName       string
	recordMaterialsPaths []string
	recordProductsPaths  []string
)

var recordCmd = &cobra.Command{
	Use: "record",
	Short: `Creates a signed link metadata file in two steps, in order to provide
evidence for supply chain steps that cannot be carried out by a single command`,
	Long: `Creates a signed link metadata file in two steps, in order to provide
evidence for supply chain steps that cannot be carried out by a single command
(for which ‘in-toto-run’ should be used). It returns a non-zero value on
failure and zero otherwise.`,
	PersistentPreRunE: recordPreRun,
}

var recordStartCmd = &cobra.Command{
	Use: "start",
	Short: `Creates a preliminary link file recording the paths and hashes of the
passed materials and signs it with the passed functionary’s key.`,
	Long: `Creates a preliminary link file recording the paths and hashes of the
passed materials and signs it with the passed functionary’s key.
The resulting link file is stored as ‘.<name>.<keyid prefix>.link-unfinished’.`,
	RunE: recordStart,
}

var recordStopCmd = &cobra.Command{
	Use:   "stop",
	Short: `Records and adds the paths and hashes of the passed products to the link metadata file and updates the signature.`,
	Long: `Expects preliminary link file ‘.<name>.<keyid prefix>.link-unfinished’ in the CWD,
signed by the passed functionary’s key. If found, it records
and adds the paths and hashes of the passed products to the
link metadata file, updates the signature and renames the
file to ‘<name>.<keyid prefix>.link’.`,
	RunE: recordStop,
}

func init() {
	rootCmd.AddCommand(recordCmd)

	recordCmd.PersistentFlags().StringVarP(
		&recordStepName,
		"name",
		"n",
		"",
		`Name for the resulting link metadata file.
It is also used to associate the link with a step defined
in an in-toto layout.`,
	)

	recordCmd.PersistentFlags().StringVarP(
		&keyPath,
		"key",
		"k",
		"",
		`Path to a private key file to sign the resulting link metadata.
The keyid prefix is used as an infix for the link metadata filename,
i.e. ‘<name>.<keyid prefix>.link’. See ‘–key-type’ for available
formats. Passing one of ‘–key’ or ‘–gpg’ is required.`,
	)

	recordCmd.MarkPersistentFlagRequired("name")

	// Record Start Command
	recordCmd.AddCommand(recordStartCmd)

	recordStartCmd.Flags().StringArrayVarP(
		&recordMaterialsPaths,
		"materials",
		"m",
		[]string{},
		`Paths to files or directories, whose paths and hashes
are stored in the resulting link metadata before the
command is executed. Symlinks are followed.`,
	)

	// Record Stop Command
	recordCmd.AddCommand(recordStopCmd)

	recordStopCmd.Flags().StringArrayVarP(
		&recordProductsPaths,
		"products",
		"p",
		[]string{},
		`Paths to files or directories, whose paths and hashes
are stored in the resulting link metadata after the
command is executed. Symlinks are followed.`,
	)
}

func recordPreRun(cmd *cobra.Command, args []string) error {
	key = intoto.Key{}
	if err := key.LoadKeyDefaults(keyPath); err != nil {
		return fmt.Errorf("invalid key at %s: %w", keyPath, err)
	}

	return nil
}

func recordStart(cmd *cobra.Command, args []string) error {
	block, err := intoto.InTotoRecordStart(recordStepName, recordMaterialsPaths, key, []string{"sha256"}, []string{})
	if err != nil {
		return fmt.Errorf("failed to create start link file: %w", err)
	}

	prelimLinkName := fmt.Sprintf(intoto.PreliminaryLinkNameFormat, recordStepName, key.KeyID)
	err = block.Dump(prelimLinkName)
	if err != nil {
		return fmt.Errorf("failed to write start link file to %s: %w", prelimLinkName, err)
	}

	return nil
}

func recordStop(cmd *cobra.Command, args []string) error {
	var prelimLinkMb intoto.Metablock
	prelimLinkName := fmt.Sprintf(intoto.PreliminaryLinkNameFormat, recordStepName, key.KeyID)
	if err := prelimLinkMb.Load(prelimLinkName); err != nil {
		return fmt.Errorf("failed to load start link file at %s: %w", prelimLinkName, err)
	}

	linkMb, err := intoto.InTotoRecordStop(prelimLinkMb, recordProductsPaths, key, []string{"sha256"}, []string{})
	if err != nil {
		return fmt.Errorf("failed to create stop link file: %w", err)
	}

	linkName := fmt.Sprintf(intoto.LinkNameFormat, recordStepName, key.KeyID)
	err = linkMb.Dump(linkName)
	if err != nil {
		return fmt.Errorf("failed to write stop link file to %s: %w", prelimLinkName, err)
	}

	return nil
}
