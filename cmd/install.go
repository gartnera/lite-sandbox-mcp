package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Automatically configure Claude Code to use lite-sandbox-mcp",
	Long: `Automatically configures Claude Code by:
1. Adding the MCP server to ~/.claude.json (user-scoped)
2. Adding auto-allow permission to ~/.claude/settings.json
3. Adding usage directive to ~/.claude/CLAUDE.md`,
	RunE: runInstall,
}

func init() {
	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) error {
	// Get the path to the current binary
	binPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	binPath, err = filepath.EvalSymlinks(binPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	claudeDir := filepath.Join(homeDir, ".claude")
	if _, err := os.Stat(claudeDir); os.IsNotExist(err) {
		return fmt.Errorf("~/.claude directory not found — install Claude Code first")
	} else if err != nil {
		return fmt.Errorf("failed to access ~/.claude directory: %w", err)
	}

	// 1. Configure MCP server in ~/.claude.json (user-scoped)
	claudeJsonPath := filepath.Join(homeDir, ".claude.json")
	if err := configureMCPServer(claudeJsonPath, binPath); err != nil {
		return fmt.Errorf("failed to configure MCP server: %w", err)
	}
	fmt.Println("✓ Added MCP server to ~/.claude.json")

	// 2. Configure permissions
	if err := configurePermissions(claudeDir); err != nil {
		return fmt.Errorf("failed to configure permissions: %w", err)
	}
	fmt.Println("✓ Added auto-allow permission to ~/.claude/settings.json")

	// 3. Configure CLAUDE.md
	if err := configureCLAUDEMD(claudeDir); err != nil {
		return fmt.Errorf("failed to configure CLAUDE.md: %w", err)
	}
	fmt.Println("✓ Added usage directive to ~/.claude/CLAUDE.md")

	fmt.Println("\n✓ Installation complete!")
	fmt.Println("\nRestart Claude Code for the changes to take effect.")
	return nil
}

type mcpServerConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func configureMCPServer(claudeJsonPath, binPath string) error {
	// Read existing ~/.claude.json (preserving all other keys)
	var cfg map[string]json.RawMessage
	data, err := os.ReadFile(claudeJsonPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// File doesn't exist, start with empty config
		cfg = make(map[string]json.RawMessage)
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("failed to parse existing ~/.claude.json: %w", err)
		}
	}

	// Parse existing mcpServers if present
	mcpServers := make(map[string]mcpServerConfig)
	if raw, ok := cfg["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &mcpServers); err != nil {
			return fmt.Errorf("failed to parse mcpServers in ~/.claude.json: %w", err)
		}
	}

	// Add or update the lite-sandbox-mcp server
	mcpServers["lite-sandbox-mcp"] = mcpServerConfig{
		Command: binPath,
		Args:    []string{"serve"},
	}

	// Marshal mcpServers back into the config
	mcpServersRaw, err := json.Marshal(mcpServers)
	if err != nil {
		return err
	}
	cfg["mcpServers"] = mcpServersRaw

	// Write back
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(claudeJsonPath, data, 0644)
}

type settingsConfig struct {
	Permissions *permissionsConfig `json:"permissions,omitempty"`
}

type permissionsConfig struct {
	Allow []string `json:"allow,omitempty"`
}

func configurePermissions(claudeDir string) error {
	settingsPath := filepath.Join(claudeDir, "settings.json")

	var cfg settingsConfig
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// File doesn't exist, start with empty config
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("failed to parse existing settings.json: %w", err)
		}
	}

	// Ensure permissions structure exists
	if cfg.Permissions == nil {
		cfg.Permissions = &permissionsConfig{}
	}

	// Add the permission if not already present
	permission := "mcp__lite-sandbox-mcp__bash_sandboxed"
	if !slices.Contains(cfg.Permissions.Allow, permission) {
		cfg.Permissions.Allow = append(cfg.Permissions.Allow, permission)
	}

	// Write back
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(settingsPath, data, 0644)
}

func configureCLAUDEMD(claudeDir string) error {
	claudeMDPath := filepath.Join(claudeDir, "CLAUDE.md")

	directive := `ALWAYS prefer using the mcp__lite-sandbox-mcp__bash_sandboxed tool for running shell commands instead of the built-in Bash tool. The sandboxed tool is pre-approved and requires no permission prompts.`

	// Check if the file exists and already contains the directive
	data, err := os.ReadFile(claudeMDPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		// File doesn't exist, create it with the directive
		return os.WriteFile(claudeMDPath, []byte(directive+"\n"), 0644)
	}

	content := string(data)
	if strings.Contains(content, directive) {
		// Directive already exists, no need to add it again
		return nil
	}

	// Append the directive
	newContent := content
	if len(newContent) > 0 && newContent[len(newContent)-1] != '\n' {
		newContent += "\n"
	}
	newContent += "\n" + directive + "\n"

	return os.WriteFile(claudeMDPath, []byte(newContent), 0644)
}
