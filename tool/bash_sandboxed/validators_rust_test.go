package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestValidateCargoArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		rustCfg   *config.RustConfig
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "cargo build allowed",
			command: "cargo build",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo build --release allowed",
			command: "cargo build --release",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo check allowed",
			command: "cargo check",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo test allowed",
			command: "cargo test",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo test with filter allowed",
			command: "cargo test my_test",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo run allowed",
			command: "cargo run",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo run with args allowed",
			command: "cargo run -- --arg1 value",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo fmt allowed",
			command: "cargo fmt",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo clippy allowed",
			command: "cargo clippy",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo clippy with args allowed",
			command: "cargo clippy -- -D warnings",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo add allowed",
			command: "cargo add serde",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo remove allowed",
			command: "cargo remove serde",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo new allowed",
			command: "cargo new my-project",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo init allowed",
			command: "cargo init",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo doc allowed",
			command: "cargo doc --open",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo clean allowed",
			command: "cargo clean",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo bench allowed",
			command: "cargo bench",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo update allowed",
			command: "cargo update",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo tree allowed",
			command: "cargo tree",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo metadata allowed",
			command: "cargo metadata --format-version 1",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo fix allowed",
			command: "cargo fix --allow-dirty",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo version allowed",
			command: "cargo version",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},

		// cargo install variants
		{
			name:    "cargo install --path local allowed",
			command: "cargo install --path .",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo install --path=local allowed",
			command: "cargo install --path=./my-crate",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:      "cargo install remote crate blocked",
			command:   "cargo install ripgrep",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "remote crate references",
		},
		{
			name:      "cargo install remote crate with version blocked",
			command:   "cargo install ripgrep --version 13.0.0",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "remote crate references",
		},

		// cargo publish
		{
			name:      "cargo publish blocked by default",
			command:   "cargo publish",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "runtimes.rust.publish is disabled",
		},
		{
			name:      "cargo publish blocked when publish=false",
			command:   "cargo publish",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true), Publish: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.rust.publish is disabled",
		},
		{
			name:    "cargo publish allowed when publish=true",
			command: "cargo publish",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo publish with flags allowed when publish=true",
			command: "cargo publish --dry-run",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},

		// Blocked subcommands
		{
			name:      "cargo login blocked",
			command:   "cargo login",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "cargo logout blocked",
			command:   "cargo logout",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "cargo owner blocked",
			command:   "cargo owner --add user",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "cargo yank blocked",
			command:   "cargo yank --vers 1.0.0",
			rustCfg:   &config.RustConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "not allowed",
		},

		// Edge cases
		{
			name:    "bare cargo command allowed",
			command: "cargo",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo with only flags allowed",
			command: "cargo --version",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo with -C flag allowed",
			command: "cargo -C /path/to/dir build",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "cargo with --manifest-path flag allowed",
			command: "cargo --manifest-path Cargo.toml build",
			rustCfg: &config.RustConfig{Enabled: boolPtr(true)},
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

			err = validateCargoArgs(args, tt.rustCfg)
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
