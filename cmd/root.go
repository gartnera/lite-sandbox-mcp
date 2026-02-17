package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "lite-sandbox",
	Short: "A lightweight sandboxed MCP server",
}

func Execute() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
