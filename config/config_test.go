package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPath(t *testing.T) {
	p, err := Path()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filepath.Base(p) != "config.yaml" {
		t.Fatalf("expected config.yaml, got %s", filepath.Base(p))
	}
	if filepath.Base(filepath.Dir(p)) != appName {
		t.Fatalf("expected parent dir %s, got %s", appName, filepath.Base(filepath.Dir(p)))
	}
}

func TestLoadSave(t *testing.T) {
	// Override the config path to a temp dir.
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	// Load should return zero-value config when file doesn't exist.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ExtraCommands) != 0 {
		t.Fatalf("expected empty extra commands, got %v", cfg.ExtraCommands)
	}

	// Save and reload.
	cfg.ExtraCommands = []string{"curl", "wget"}
	if err := Save(cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}

	cfg2, err := Load()
	if err != nil {
		t.Fatalf("load error: %v", err)
	}
	if len(cfg2.ExtraCommands) != 2 || cfg2.ExtraCommands[0] != "curl" || cfg2.ExtraCommands[1] != "wget" {
		t.Fatalf("expected [curl wget], got %v", cfg2.ExtraCommands)
	}
}

func TestLoadUnknownFields(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	data := []byte("extra_commands:\n  - curl\nfuture_field: value\n")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.ExtraCommands) != 1 || cfg.ExtraCommands[0] != "curl" {
		t.Fatalf("expected [curl], got %v", cfg.ExtraCommands)
	}
}

func TestWatch(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changed := make(chan *Config, 1)
	go func() {
		_ = Watch(ctx, func(cfg *Config) {
			changed <- cfg
		})
	}()

	// Give the watcher time to start.
	time.Sleep(100 * time.Millisecond)

	// Write a config file to trigger the watcher.
	cfg := &Config{ExtraCommands: []string{"python3"}}
	if err := Save(cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}

	select {
	case got := <-changed:
		if len(got.ExtraCommands) != 1 || got.ExtraCommands[0] != "python3" {
			t.Fatalf("expected [python3], got %v", got.ExtraCommands)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config change notification")
	}
}
