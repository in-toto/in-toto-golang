package main

import (
	"encoding/json"
	"fmt"

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
	Short: "Output the key layout for a given key",
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

	b, err := json.Marshal(key)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", b)

	return nil
}
