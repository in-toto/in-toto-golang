package cmd

import (
	"fmt"
	"path/filepath"

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
	PersistentPreRunE: getKeyCert,
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

	recordCmd.PersistentFlags().StringVarP(
		&certPath,
		"cert",
		"c",
		"",
		`Path to a PEM formatted certificate that corresponds
with the provided key.`,
	)

	recordCmd.PersistentFlags().StringVarP(
		&outDir,
		"metadata-directory",
		"d",
		"./",
		`Directory to store link metadata`,
	)

	recordCmd.PersistentFlags().StringArrayVarP(
		&lStripPaths,
		"lstrip-paths",
		"l",
		[]string{},
		`Path prefixes used to left-strip artifact paths before storing
them to the resulting link metadata. If multiple prefixes
are specified, only a single prefix can match the path of
any artifact and that is then left-stripped. All prefixes
are checked to ensure none of them are a left substring
of another.`,
	)

	recordCmd.PersistentFlags().StringArrayVarP(
		&exclude,
		"exclude",
		"e",
		[]string{},
		`Path patterns to match paths that should not be recorded as 
‘materials’ or ‘products’. Passed patterns override patterns defined
in environment variables or config files. See Config docs for details.`,
	)

	recordCmd.PersistentFlags().StringVar(
		&spiffeUDS,
		"spiffe-workload-api-path",
		"",
		"UDS path for SPIFFE workload API",
	)

	recordCmd.PersistentFlags().BoolVar(
		&lineNormalization,
		"normalize-line-endings",
		false,
		`Enable line normalization in order to support different
operating systems. It is done by replacing all line separators
with a new line character.`,
	)

	recordCmd.PersistentFlags().BoolVar(
		&followSymlinkDirs,
		"follow-symlink-dirs",
		false,
		`Follow symlinked directories to their targets. Note: this parameter
toggles following linked directories only, linked files are always
recorded independently of this parameter.`,
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

func recordStart(cmd *cobra.Command, args []string) error {
	block, err := intoto.InTotoRecordStart(recordStepName, recordMaterialsPaths, key, []string{"sha256"}, exclude, lStripPaths, lineNormalization, followSymlinkDirs)
	if err != nil {
		return fmt.Errorf("failed to create start link file: %w", err)
	}

	prelimLinkName := fmt.Sprintf(intoto.PreliminaryLinkNameFormat, recordStepName, key.KeyID)
	prelimLinkPath := filepath.Join(outDir, prelimLinkName)
	err = block.Dump(prelimLinkPath)
	if err != nil {
		return fmt.Errorf("failed to write start link file to %s: %w", prelimLinkName, err)
	}

	return nil
}

func recordStop(cmd *cobra.Command, args []string) error {
	var prelimLinkMb intoto.Metablock
	prelimLinkName := fmt.Sprintf(intoto.PreliminaryLinkNameFormat, recordStepName, key.KeyID)
	prelimLinkPath := filepath.Join(outDir, prelimLinkName)
	if err := prelimLinkMb.Load(prelimLinkPath); err != nil {
		return fmt.Errorf("failed to load start link file at %s: %w", prelimLinkName, err)
	}

	linkMb, err := intoto.InTotoRecordStop(prelimLinkMb, recordProductsPaths, key, []string{"sha256"}, exclude, lStripPaths, lineNormalization, followSymlinkDirs)
	if err != nil {
		return fmt.Errorf("failed to create stop link file: %w", err)
	}

	linkName := fmt.Sprintf(intoto.LinkNameFormat, recordStepName, key.KeyID)
	linkPath := filepath.Join(outDir, linkName)
	err = linkMb.Dump(linkPath)
	if err != nil {
		return fmt.Errorf("failed to write stop link file to %s: %w", prelimLinkName, err)
	}

	return nil
}
