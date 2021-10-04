package main

import (
	"github.com/spf13/cobra"
	"os"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:
Bash:
  $ source <(in-toto completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ in-toto completion bash > /etc/bash_completion.d/in-toto
  # macOS:
  $ in-toto completion bash > /usr/local/etc/bash_completion.d/in-toto
Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc
  # To load completions for each session, execute once:
  $ in-toto completion zsh > "${fpath[1]}/_in-toto"
  # You will need to start a new shell for this setup to take effect.
fish:
  $ in-toto completion fish | source
  # To load completions for each session, execute once:
  $ in-toto completion fish > ~/.config/fish/completions/in-toto.fish
PowerShell:
  PS> in-toto completion powershell | Out-String | Invoke-Expression
  # To load completions for every new session, run:
  PS> in-toto completion powershell > in-toto.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactValidArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			_ = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			_ = cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			_ = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
