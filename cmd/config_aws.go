package cmd

import (
	"fmt"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"github.com/spf13/cobra"
)

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Manage AWS CLI permission settings",
}

var awsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current AWS configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil {
			fmt.Println("AWS: disabled (not configured)")
			return nil
		}

		fmt.Println("AWS Configuration:")
		if cfg.AWS.AllowsRawCredentials() {
			fmt.Println("  Mode: allow_raw_credentials")
			fmt.Println("  Description: AWS CLI reads from ~/.aws/credentials directly")
			fmt.Println("  Security: Less secure (long-term credentials)")
			fmt.Println("  ~/.aws: Accessible")
			fmt.Println("  ~/.ssh: Blocked")
		} else if cfg.AWS.UsesIMDS() {
			fmt.Printf("  Mode: force_profile (%s)\n", cfg.AWS.IMDSProfile())
			fmt.Println("  Description: AWS CLI uses IMDS server with temporary credentials")
			fmt.Println("  Security: More secure (1-hour STS tokens)")
			fmt.Println("  ~/.aws: Blocked")
			fmt.Println("  ~/.ssh: Blocked")
		} else {
			fmt.Println("  Mode: disabled")
			fmt.Println("  AWS CLI commands are not allowed")
		}

		return nil
	},
}

var awsAllowRawCredentialsCmd = &cobra.Command{
	Use:   "allow-raw-credentials",
	Short: "Allow AWS CLI to read from ~/.aws/credentials directly (less secure)",
	Long: `Enable allow_raw_credentials mode for AWS CLI.

In this mode:
- AWS CLI reads credentials from ~/.aws/credentials directly
- No IMDS server is started
- ~/.aws is NOT blocked (accessible to commands)
- ~/.ssh is ALWAYS blocked
- Uses long-term credentials (no automatic rotation)

This mode is simpler but less secure. Use for development/testing only.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}

		// Enable raw credentials, clear force_profile
		t := true
		cfg.AWS.AllowRawCredentials = &t
		cfg.AWS.ForceProfile = ""

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("AWS configured for raw credential access")
		fmt.Println("  ~/.aws/credentials will be readable by AWS CLI")
		fmt.Println("  ~/.ssh will remain blocked")
		return nil
	},
}

var awsForceProfileCmd = &cobra.Command{
	Use:   "force-profile <profile-name>",
	Short: "Force AWS CLI to use IMDS server with specified profile (more secure)",
	Long: `Enable force_profile mode for AWS CLI.

In this mode:
- AWS CLI gets credentials from local IMDS server
- IMDS server uses specified profile to fetch temporary STS credentials
- ~/.aws is BLOCKED (not accessible to commands)
- ~/.ssh is ALWAYS blocked
- Uses temporary 1-hour STS session tokens
- Credentials auto-refresh before expiry

This mode is more secure and recommended for production use.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		profile := args[0]

		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		if cfg.AWS == nil {
			cfg.AWS = &config.AWSConfig{}
		}

		// Set force_profile, clear allow_raw_credentials
		cfg.AWS.ForceProfile = profile
		cfg.AWS.AllowRawCredentials = nil

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Printf("AWS configured to force profile: %s\n", profile)
		fmt.Println("  IMDS server will provide temporary credentials")
		fmt.Println("  ~/.aws will be blocked")
		fmt.Println("  ~/.ssh will remain blocked")
		return nil
	},
}

var awsDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable AWS CLI entirely",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		// Clear all AWS settings
		cfg.AWS = nil

		if err := saveConfig(cfg); err != nil {
			return err
		}

		fmt.Println("AWS disabled")
		fmt.Println("  AWS CLI commands will not be allowed")
		return nil
	},
}

func init() {
	awsCmd.AddCommand(awsShowCmd)
	awsCmd.AddCommand(awsAllowRawCredentialsCmd)
	awsCmd.AddCommand(awsForceProfileCmd)
	awsCmd.AddCommand(awsDisableCmd)
	configCmd.AddCommand(awsCmd)
}
