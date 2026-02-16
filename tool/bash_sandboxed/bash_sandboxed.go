package bash_sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Sandbox executes bash commands after parsing and validating them against
// the built-in allowlist plus any extra commands from config.
type Sandbox struct {
	mu             sync.RWMutex
	extraCommands  map[string]bool
	gitConfig      *config.GitConfig
	runtimesConfig *config.RuntimesConfig
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
	s.gitConfig = cfg.Git
	s.runtimesConfig = cfg.Runtimes
	s.mu.Unlock()
}

// getExtraCommands returns a snapshot of the current extra commands.
func (s *Sandbox) getExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraCommands
}

// getGitConfig returns a snapshot of the current git config.
func (s *Sandbox) getGitConfig() *config.GitConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gitConfig
}

// getRuntimesConfig returns a snapshot of the current runtimes config.
func (s *Sandbox) getRuntimesConfig() *config.RuntimesConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimesConfig
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

// blockedEnvVars lists environment variables that cannot be assigned in sandboxed commands.
// PATH is inherited but cannot be mutated (prevents command whitelist bypass).
// Others prevent shared library injection, auto-sourced scripts, and unexpected behavior.
var blockedEnvVars = map[string]string{
	"PATH":            "mutating PATH could bypass the command whitelist",
	"LD_PRELOAD":      "shared library injection",
	"LD_LIBRARY_PATH": "shared library injection",
	"BASH_ENV":        "auto-sourced script injection",
	"ENV":             "auto-sourced script injection",
	"CDPATH":          "unexpected directory resolution",
	"PROMPT_COMMAND":  "arbitrary command execution",
}

// validateAssigns checks that none of the assignments target a blocked environment variable.
func validateAssigns(assigns []*syntax.Assign) error {
	for _, a := range assigns {
		if a.Name == nil {
			continue
		}
		if reason, blocked := blockedEnvVars[a.Name.Value]; blocked {
			return fmt.Errorf("setting %s is not allowed: %s", a.Name.Value, reason)
		}
	}
	return nil
}

// validate walks the parsed AST and enforces:
// 1. All commands must be in the allowedCommands whitelist or extra commands
// 2. Redirections must pass validateRedirect (safe subset only)
// 3. No process substitutions are permitted
// 4. Per-command argument validators (e.g., blocking find -exec)
// 5. Blocked environment variable assignments (PATH, LD_PRELOAD, etc.)
func (s *Sandbox) validate(f *syntax.File) error {
	extra := s.getExtraCommands()
	gitCfg := s.getGitConfig()
	runtimesCfg := s.getRuntimesConfig()
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
			if err := validateAssigns(n.Assigns); err != nil {
				validationErr = err
				return false
			}
			if len(n.Args) > 0 {
				cmdName := extractCommandName(n.Args[0])
				if cmdName == "" {
					validationErr = fmt.Errorf("dynamic command names are not allowed")
					return false
				}
				// Handle runtime commands dynamically based on config
				if cmdName == "go" {
					if runtimesCfg == nil || runtimesCfg.Go == nil || !runtimesCfg.Go.GoEnabled() {
						validationErr = fmt.Errorf("command %q is not allowed (runtimes.go.enabled is disabled)", cmdName)
						return false
					}
					if err := validateGoArgs(n.Args, runtimesCfg.Go); err != nil {
						validationErr = err
						return false
					}
				} else if !allowedCommands[cmdName] && !extra[cmdName] {
					validationErr = fmt.Errorf("command %q is not allowed", cmdName)
					return false
				} else if cmdName == "git" {
					if err := validateGitArgs(n.Args, gitCfg); err != nil {
						validationErr = err
						return false
					}
				} else if validator, ok := commandArgValidators[cmdName]; ok {
					if err := validator(n.Args); err != nil {
						validationErr = err
						return false
					}
				}
			}
		case *syntax.DeclClause:
			if err := validateAssigns(n.Args); err != nil {
				validationErr = err
				return false
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

	var out bytes.Buffer
	runner, err := interp.New(
		interp.Dir(workDir),
		interp.StdIO(nil, &out, &out),
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			hc := interp.HandlerCtx(ctx)
			if err := validateExpandedPaths(args, hc.Dir, allowedPaths); err != nil {
				return nil, err
			}
			return args, nil
		}),
		interp.OpenHandler(func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			hc := interp.HandlerCtx(ctx)
			if err := validateOpenPath(path, hc.Dir, allowedPaths); err != nil {
				return nil, err
			}
			return interp.DefaultOpenHandler()(ctx, path, flag, perm)
		}),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create interpreter: %w", err)
	}

	err = runner.Run(ctx, f)
	output := out.String()
	if err != nil {
		return output, fmt.Errorf("command failed: %w\noutput: %s", err, output)
	}
	return output, nil
}
