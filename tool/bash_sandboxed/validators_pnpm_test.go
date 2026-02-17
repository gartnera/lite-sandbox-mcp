package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestValidatePnpmArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		pnpmCfg   *config.PnpmConfig
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "pnpm install allowed",
			command: "pnpm install",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm add allowed",
			command: "pnpm add react",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm remove allowed",
			command: "pnpm remove lodash",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm update allowed",
			command: "pnpm update",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm test allowed",
			command: "pnpm test",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm run allowed",
			command: "pnpm run build",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm list allowed",
			command: "pnpm list",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm outdated allowed",
			command: "pnpm outdated",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm why allowed",
			command: "pnpm why react",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm audit allowed",
			command: "pnpm audit",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm exec allowed",
			command: "pnpm exec eslint .",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm create allowed",
			command: "pnpm create vite",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm init allowed",
			command: "pnpm init",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm store status allowed",
			command: "pnpm store status",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm prune allowed",
			command: "pnpm prune",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},

		// pnpm dlx variants (all blocked)
		{
			name:      "pnpm dlx blocked",
			command:   "pnpm dlx cowsay hello",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},
		{
			name:      "pnpm dlx with flags blocked",
			command:   "pnpm dlx -y cowsay hello",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},
		{
			name:      "pnpm dlx with package@version blocked",
			command:   "pnpm dlx cowsay@latest hello",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},

		// pnpm publish
		{
			name:      "pnpm publish blocked by default",
			command:   "pnpm publish",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "runtimes.pnpm.publish is disabled",
		},
		{
			name:      "pnpm publish blocked when publish=false",
			command:   "pnpm publish",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true), Publish: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.pnpm.publish is disabled",
		},
		{
			name:    "pnpm publish allowed when publish=true",
			command: "pnpm publish",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm publish with flags allowed when publish=true",
			command: "pnpm publish --tag beta",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},

		// Edge cases
		{
			name:    "bare pnpm command allowed",
			command: "pnpm",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm with only flags allowed",
			command: "pnpm --version",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm with -C flag allowed",
			command: "pnpm -C /path/to/dir install",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm with --dir flag allowed",
			command: "pnpm --dir /path/to/dir install",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("failed to parse command: %v", err)
			}

			var args []*syntax.Word
			syntax.Walk(f, func(node syntax.Node) bool {
				if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
					args = call.Args
					return false
				}
				return true
			})

			err = validatePnpmArgs(args, tt.pnpmCfg)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
