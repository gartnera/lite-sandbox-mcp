package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// readable-paths

var readablePathsCmd = &cobra.Command{
	Use:   "readable-paths",
	Short: "Manage additional readable paths",
}

var readablePathsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List additional readable paths",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, p := range cfg.ReadablePaths {
			fmt.Println(p)
		}
		return nil
	},
}

var readablePathsAddCmd = &cobra.Command{
	Use:   "add <path>...",
	Short: "Add paths to the readable paths list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		existing := make(map[string]bool, len(cfg.ReadablePaths))
		for _, p := range cfg.ReadablePaths {
			existing[p] = true
		}
		for _, p := range args {
			if !existing[p] {
				cfg.ReadablePaths = append(cfg.ReadablePaths, p)
				existing[p] = true
			}
		}
		return saveConfig(cfg)
	},
}

var readablePathsRemoveCmd = &cobra.Command{
	Use:   "remove <path>...",
	Short: "Remove paths from the readable paths list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		toRemove := make(map[string]bool, len(args))
		for _, p := range args {
			toRemove[p] = true
		}
		filtered := cfg.ReadablePaths[:0]
		for _, p := range cfg.ReadablePaths {
			if !toRemove[p] {
				filtered = append(filtered, p)
			}
		}
		cfg.ReadablePaths = filtered
		return saveConfig(cfg)
	},
}

// writable-paths

var writablePathsCmd = &cobra.Command{
	Use:   "writable-paths",
	Short: "Manage additional writable paths",
}

var writablePathsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List additional writable paths",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, p := range cfg.WritablePaths {
			fmt.Println(p)
		}
		return nil
	},
}

var writablePathsAddCmd = &cobra.Command{
	Use:   "add <path>...",
	Short: "Add paths to the writable paths list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		existing := make(map[string]bool, len(cfg.WritablePaths))
		for _, p := range cfg.WritablePaths {
			existing[p] = true
		}
		for _, p := range args {
			if !existing[p] {
				cfg.WritablePaths = append(cfg.WritablePaths, p)
				existing[p] = true
			}
		}
		return saveConfig(cfg)
	},
}

var writablePathsRemoveCmd = &cobra.Command{
	Use:   "remove <path>...",
	Short: "Remove paths from the writable paths list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		toRemove := make(map[string]bool, len(args))
		for _, p := range args {
			toRemove[p] = true
		}
		filtered := cfg.WritablePaths[:0]
		for _, p := range cfg.WritablePaths {
			if !toRemove[p] {
				filtered = append(filtered, p)
			}
		}
		cfg.WritablePaths = filtered
		return saveConfig(cfg)
	},
}

func init() {
	readablePathsCmd.AddCommand(readablePathsListCmd)
	readablePathsCmd.AddCommand(readablePathsAddCmd)
	readablePathsCmd.AddCommand(readablePathsRemoveCmd)
	configCmd.AddCommand(readablePathsCmd)

	writablePathsCmd.AddCommand(writablePathsListCmd)
	writablePathsCmd.AddCommand(writablePathsAddCmd)
	writablePathsCmd.AddCommand(writablePathsRemoveCmd)
	configCmd.AddCommand(writablePathsCmd)
}
