package bash_sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"mvdan.cc/sh/v3/syntax"
)

// Sandbox executes bash commands after parsing and validating them against
// the built-in allowlist plus any extra commands from config.
type Sandbox struct {
	mu              sync.RWMutex
	extraCommands   map[string]bool
}

// NewSandbox creates a Sandbox with no extra commands.
func NewSandbox() *Sandbox {
	return &Sandbox{}
}

// UpdateConfig replaces the sandbox configuration with the provided config.
func (s *Sandbox) UpdateConfig(cfg *config.Config) {
	m := make(map[string]bool, len(cfg.ExtraCommands))
	for _, c := range cfg.ExtraCommands {
		m[c] = true
	}
	s.mu.Lock()
	s.extraCommands = m
	s.mu.Unlock()
}

// getExtraCommands returns a snapshot of the current extra commands.
func (s *Sandbox) getExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraCommands
}

// ParseBash parses a command string as bash and returns the AST.
func ParseBash(command string) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse bash: %w", err)
	}
	return f, nil
}

// validate walks the parsed AST and enforces:
// 1. All commands must be in the allowedCommands whitelist or extra commands
// 2. Redirections must pass validateRedirect (safe subset only)
// 3. No process substitutions are permitted
// 4. Per-command argument validators (e.g., blocking find -exec)
func (s *Sandbox) validate(f *syntax.File) error {
	extra := s.getExtraCommands()
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			for _, r := range n.Redirs {
				if err := validateRedirect(r); err != nil {
					validationErr = err
					return false
				}
			}
		case *syntax.CallExpr:
			if len(n.Args) > 0 {
				cmdName := extractCommandName(n.Args[0])
				if cmdName == "" {
					validationErr = fmt.Errorf("dynamic command names are not allowed")
					return false
				}
				if !allowedCommands[cmdName] && !extra[cmdName] {
					validationErr = fmt.Errorf("command %q is not allowed", cmdName)
					return false
				}
				if validator, ok := commandArgValidators[cmdName]; ok {
					if err := validator(n.Args); err != nil {
						validationErr = err
						return false
					}
				}
			}
		case *syntax.ProcSubst:
			validationErr = fmt.Errorf("process substitutions are not allowed")
			return false
		case *syntax.CoprocClause:
			validationErr = fmt.Errorf("coprocesses are not allowed")
			return false
		}
		return true
	})
	return validationErr
}

// extractCommandName returns the literal name of a command from a Word node.
// Returns empty string if the command name cannot be statically determined.
func extractCommandName(w *syntax.Word) string {
	return w.Lit()
}

// Execute parses, validates, and executes a bash command.
// workDir is the working directory for the command and for resolving relative paths.
// allowedPaths are absolute directories that the command is permitted to access.
// It returns the combined stdout and stderr output.
func (s *Sandbox) Execute(ctx context.Context, command string, workDir string, allowedPaths []string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	f, err := ParseBash(command)
	if err != nil {
		return "", err
	}

	if err := s.validate(f); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validatePaths(f, workDir, allowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validateRedirectPaths(f, workDir, allowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = workDir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	output := out.String()
	if err != nil {
		return output, fmt.Errorf("command failed: %w\noutput: %s", err, output)
	}
	return output, nil
}
