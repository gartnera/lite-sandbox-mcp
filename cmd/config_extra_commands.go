package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var extraCommandsCmd = &cobra.Command{
	Use:   "extra-commands",
	Short: "Manage extra allowed commands",
}

var extraCommandsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List extra allowed commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		for _, c := range cfg.ExtraCommands {
			fmt.Println(c)
		}
		return nil
	},
}

var extraCommandsAddCmd = &cobra.Command{
	Use:   "add <command>...",
	Short: "Add commands to the extra allowed list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		existing := make(map[string]bool, len(cfg.ExtraCommands))
		for _, c := range cfg.ExtraCommands {
			existing[c] = true
		}
		for _, c := range args {
			if !existing[c] {
				cfg.ExtraCommands = append(cfg.ExtraCommands, c)
				existing[c] = true
			}
		}
		return saveConfig(cfg)
	},
}

var extraCommandsRemoveCmd = &cobra.Command{
	Use:   "remove <command>...",
	Short: "Remove commands from the extra allowed list",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		toRemove := make(map[string]bool, len(args))
		for _, c := range args {
			toRemove[c] = true
		}
		filtered := cfg.ExtraCommands[:0]
		for _, c := range cfg.ExtraCommands {
			if !toRemove[c] {
				filtered = append(filtered, c)
			}
		}
		cfg.ExtraCommands = filtered
		return saveConfig(cfg)
	},
}

func init() {
	extraCommandsCmd.AddCommand(extraCommandsListCmd)
	extraCommandsCmd.AddCommand(extraCommandsAddCmd)
	extraCommandsCmd.AddCommand(extraCommandsRemoveCmd)
	configCmd.AddCommand(extraCommandsCmd)
}
