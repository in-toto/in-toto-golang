package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key management commands",
}

var keyIDCmd = &cobra.Command{
	Use:   "id <file>",
	Short: "Output the key id for a given key",
	Long:  "Output the key id for a given key",
	Args:  cobra.ExactArgs(1),
	RunE:  keyID,
}

var keyLayoutCmd = &cobra.Command{
	Use:   "layout <file>",
	Short: "Output the key layout for a given key in <KEYID>: <KEYOBJ> format",
	Long:  "Output is a json formatted pubkey suitable for embedding in a layout file",
	Args:  cobra.ExactArgs(1),
	RunE:  keyLayout,
}

func init() {
	rootCmd.AddCommand(keyCmd)

	keyCmd.AddCommand(keyIDCmd)
	keyCmd.AddCommand(keyLayoutCmd)
}

func keyID(cmd *cobra.Command, args []string) error {
	var key intoto.Key

	err := key.LoadKeyDefaults(args[0])
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", key.KeyID)

	return nil
}

func keyLayout(cmd *cobra.Command, args []string) error {
	var key intoto.Key

	err := key.LoadKeyDefaults(args[0])
	if err != nil {
		return err
	}

	// removed the private key from the struct such that it is not printed for use in the layout
	key.KeyVal.Private = ""

	b, err := json.Marshal(key)
	if err != nil {
		return err
	}

	s2 := strings.ReplaceAll(string(b), `"private":"",`, "")
	fmt.Printf(`"%v": %s`, key.KeyID, s2)

	return nil
}
