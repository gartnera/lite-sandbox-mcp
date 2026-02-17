package cmd

import (
	"github.com/gartnera/lite-sandbox-mcp/os_sandbox"
	"github.com/spf13/cobra"
)

var sandboxWorkerCmd = &cobra.Command{
	Use:           "sandbox-worker",
	Short:         "Run as a sandbox worker process (internal, runs inside bwrap)",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return os_sandbox.RunWorker()
	},
}

func init() {
	rootCmd.AddCommand(sandboxWorkerCmd)
}
