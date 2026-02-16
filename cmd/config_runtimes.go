package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"github.com/spf13/cobra"
)

var runtimesCmd = &cobra.Command{
	Use:   "runtimes",
	Short: "Manage runtime permission settings",
}

var runtimesShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			fmt.Println("No runtime settings configured (all defaults)")
			return nil
		}
		fmt.Println("Runtimes:")
		if cfg.Runtimes.Go != nil {
			fmt.Println("  go:")
			fmt.Printf("    enabled:  %v\n", cfg.Runtimes.Go.GoEnabled())
			fmt.Printf("    generate: %v\n", cfg.Runtimes.Go.GoGenerate())
		} else {
			fmt.Println("  go: (defaults)")
			fmt.Printf("    enabled:  %v\n", false)
			fmt.Printf("    generate: %v\n", false)
		}
		return nil
	},
}

// Go runtime commands
var goRuntimeCmd = &cobra.Command{
	Use:   "go",
	Short: "Manage Go runtime permission settings",
}

var goRuntimeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current Go runtime permission settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		g := &config.GoConfig{}
		if cfg.Runtimes != nil && cfg.Runtimes.Go != nil {
			g = cfg.Runtimes.Go
		}
		fmt.Printf("enabled:  %v\n", g.GoEnabled())
		fmt.Printf("generate: %v\n", g.GoGenerate())
		return nil
	},
}

var goRuntimeEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable Go runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withGenerate, _ := cmd.Flags().GetBool("with-generate")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Go == nil {
			cfg.Runtimes.Go = &config.GoConfig{}
		}

		trueVal := true
		cfg.Runtimes.Go.Enabled = &trueVal

		if withGenerate {
			cfg.Runtimes.Go.Generate = &trueVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.go.enabled set to true")
		if withGenerate {
			fmt.Println("runtimes.go.generate set to true")
		}
		return nil
	},
}

var goRuntimeDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable Go runtime commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		withGenerate, _ := cmd.Flags().GetBool("with-generate")

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if cfg.Runtimes == nil {
			cfg.Runtimes = &config.RuntimesConfig{}
		}
		if cfg.Runtimes.Go == nil {
			cfg.Runtimes.Go = &config.GoConfig{}
		}

		falseVal := false
		cfg.Runtimes.Go.Enabled = &falseVal

		if withGenerate {
			cfg.Runtimes.Go.Generate = &falseVal
		}

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("runtimes.go.enabled set to false")
		if withGenerate {
			fmt.Println("runtimes.go.generate set to false")
		}
		return nil
	},
}

func init() {
	// Add --with-generate flag to enable/disable commands
	goRuntimeEnableCmd.Flags().Bool("with-generate", false, "Also enable go generate")
	goRuntimeDisableCmd.Flags().Bool("with-generate", false, "Also disable go generate")

	// Add go subcommands
	goRuntimeCmd.AddCommand(goRuntimeShowCmd)
	goRuntimeCmd.AddCommand(goRuntimeEnableCmd)
	goRuntimeCmd.AddCommand(goRuntimeDisableCmd)

	// Add runtimes subcommands
	runtimesCmd.AddCommand(runtimesShowCmd)
	runtimesCmd.AddCommand(goRuntimeCmd)

	// Add runtimes to config
	configCmd.AddCommand(runtimesCmd)
}
