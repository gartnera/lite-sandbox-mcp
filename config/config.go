package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

const appName = "lite-sandbox-mcp"

// GitConfig controls granular git permission levels.
type GitConfig struct {
	LocalRead   *bool `yaml:"local_read,omitempty"`
	LocalWrite  *bool `yaml:"local_write,omitempty"`
	RemoteRead  *bool `yaml:"remote_read,omitempty"`
	RemoteWrite *bool `yaml:"remote_write,omitempty"`
}

// GitLocalRead returns whether local read git operations are allowed (default: true).
func (g *GitConfig) GitLocalRead() bool {
	if g == nil || g.LocalRead == nil {
		return true
	}
	return *g.LocalRead
}

// GitLocalWrite returns whether local write git operations are allowed (default: true).
func (g *GitConfig) GitLocalWrite() bool {
	if g == nil || g.LocalWrite == nil {
		return true
	}
	return *g.LocalWrite
}

// GitRemoteRead returns whether remote read git operations are allowed (default: true).
func (g *GitConfig) GitRemoteRead() bool {
	if g == nil || g.RemoteRead == nil {
		return true
	}
	return *g.RemoteRead
}

// GitRemoteWrite returns whether remote write git operations are allowed (default: false).
func (g *GitConfig) GitRemoteWrite() bool {
	if g == nil || g.RemoteWrite == nil {
		return false
	}
	return *g.RemoteWrite
}

// GoConfig controls granular Go runtime permission levels.
type GoConfig struct {
	Enabled  *bool `yaml:"enabled,omitempty"`
	Generate *bool `yaml:"generate,omitempty"`
}

// GoEnabled returns whether go commands are allowed (default: false).
func (g *GoConfig) GoEnabled() bool {
	if g == nil || g.Enabled == nil {
		return false
	}
	return *g.Enabled
}

// GoGenerate returns whether go generate is allowed (default: false).
func (g *GoConfig) GoGenerate() bool {
	if g == nil || g.Generate == nil {
		return false
	}
	return *g.Generate
}

// RuntimesConfig controls code execution runtime permissions.
type RuntimesConfig struct {
	Go *GoConfig `yaml:"go,omitempty"`
}

// Config holds all user configuration. New fields can be added over time;
// unknown YAML fields are silently ignored for forward compatibility.
type Config struct {
	ExtraCommands []string        `yaml:"extra_commands,omitempty"`
	Git           *GitConfig      `yaml:"git,omitempty"`
	Runtimes      *RuntimesConfig `yaml:"runtimes,omitempty"`
}

// Path returns the platform-appropriate config file path.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine config directory: %w", err)
	}
	return filepath.Join(dir, appName, "config.yaml"), nil
}

// Load reads and parses the config file. If the file does not exist,
// a zero-value Config is returned with no error.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config to the YAML file, creating the directory if needed.
func Save(cfg *Config) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// Watch monitors the config file for changes and calls onChange with the
// newly loaded Config. It blocks until ctx is cancelled. If the config
// directory does not exist yet, Watch creates it so fsnotify can watch it.
func Watch(ctx context.Context, onChange func(*Config)) error {
	p, err := Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watching config directory: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Only react to writes/creates of the config file itself.
			if filepath.Base(event.Name) != filepath.Base(p) {
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				cfg, err := Load()
				if err != nil {
					slog.Error("failed to reload config", "error", err)
					continue
				}
				onChange(cfg)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.Error("config watcher error", "error", err)
		}
	}
}
