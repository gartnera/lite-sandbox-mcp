package bash_sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"github.com/gartnera/lite-sandbox-mcp/os_sandbox"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Sandbox executes bash commands after parsing and validating them against
// the built-in allowlist plus any extra commands from config.
type Sandbox struct {
	mu               sync.RWMutex
	extraCommands    map[string]bool
	gitConfig        *config.GitConfig
	runtimesConfig   *config.RuntimesConfig
	runtimeReadPaths []string
	osSandbox        bool
	pool             *os_sandbox.WorkerPool
}

// NewSandbox creates a Sandbox with no extra commands.
func NewSandbox() *Sandbox {
	return &Sandbox{}
}

// UpdateConfig replaces the sandbox configuration with the provided config.
func (s *Sandbox) UpdateConfig(cfg *config.Config, workDir string) {
	m := make(map[string]bool, len(cfg.ExtraCommands))
	for _, c := range cfg.ExtraCommands {
		m[c] = true
	}
	// Detect runtime paths for read-only access (e.g., GOPATH, GOCACHE, pnpm store)
	runtimeReadPaths := detectRuntimeBinds(cfg.Runtimes)

	s.mu.Lock()
	s.extraCommands = m
	s.gitConfig = cfg.Git
	s.runtimesConfig = cfg.Runtimes
	s.runtimeReadPaths = runtimeReadPaths

	// Handle OS sandbox enable/disable
	newOSSandbox := cfg.OSSandboxEnabled()
	if newOSSandbox != s.osSandbox {
		// OS sandbox setting changed
		if s.pool != nil {
			slog.Info("closing existing worker pool")
			s.pool.Close()
			s.pool = nil
		}
		if newOSSandbox {
			slog.Info("enabling OS sandbox", "workers", cfg.OSSandboxWorkersCount())
			s.pool = os_sandbox.NewWorkerPool(cfg.OSSandboxWorkersCount(), workDir, runtimeReadPaths)
		}
		s.osSandbox = newOSSandbox
	} else if newOSSandbox && s.pool != nil {
		// OS sandbox is enabled but worker count may have changed
		// For now, we don't dynamically resize the pool
		// Could be enhanced in the future
	}
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

// RuntimeReadPaths returns the detected runtime paths that should be
// readable (but not writable) by sandboxed commands. These include paths
// like GOPATH, GOCACHE, and pnpm store directories.
func (s *Sandbox) RuntimeReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimeReadPaths
}

// Close shuts down the sandbox, closing any worker pool.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pool != nil {
		return s.pool.Close()
	}
	return nil
}

// detectRuntimeBinds detects paths needed by enabled runtimes and returns them
// as a list of directories to bind mount as writable in the OS sandbox.
func detectRuntimeBinds(runtimes *config.RuntimesConfig) []string {
	if runtimes == nil {
		return nil
	}

	var binds []string

	// Detect Go paths if Go runtime is enabled
	if runtimes.Go != nil && runtimes.Go.GoEnabled() {
		goBinds := detectGoBinds()
		binds = append(binds, goBinds...)
	}

	// Detect pnpm paths if pnpm runtime is enabled
	if runtimes.Pnpm != nil && runtimes.Pnpm.PnpmEnabled() {
		pnpmBinds := detectPnpmBinds()
		binds = append(binds, pnpmBinds...)
	}

	return binds
}

// detectGoBinds detects Go environment paths that need to be writable.
// Returns GOPATH and GOCACHE (build cache) directories.
func detectGoBinds() []string {
	cmd := exec.Command("go", "env", "GOPATH", "GOCACHE")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect Go paths", "error", err)
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var paths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "off" {
			paths = append(paths, line)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Go runtime paths", "paths", paths)
	}

	return paths
}

// detectPnpmBinds detects pnpm paths that need to be writable.
// Returns the pnpm store directory where packages are cached.
func detectPnpmBinds() []string {
	cmd := exec.Command("pnpm", "store", "path")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect pnpm paths", "error", err)
		return nil
	}

	storePath := strings.TrimSpace(string(output))
	if storePath == "" {
		return nil
	}

	paths := []string{storePath}
	slog.Info("detected pnpm runtime paths", "paths", paths)
	return paths
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
				if !allowedCommands[cmdName] && !extra[cmdName] {
					validationErr = fmt.Errorf("command %q is not allowed", cmdName)
					return false
				}
				if validator, ok := commandArgValidators[cmdName]; ok {
					if err := validator(s, n.Args); err != nil {
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
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
// It returns the combined stdout and stderr output.
func (s *Sandbox) Execute(ctx context.Context, command string, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	// Parse and validate
	f, err := ParseBash(command)
	if err != nil {
		return "", err
	}

	if err := s.validate(f); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validatePaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validateRedirectPaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Always execute using interp
	// If OS sandbox is enabled, ExecHandler will send commands to worker
	return s.executeWithInterp(ctx, f, workDir, readAllowedPaths, writeAllowedPaths)
}

// executeWithInterp executes the parsed command using interp.
// If OS sandbox is enabled, ExecHandler delegates to worker pool.
func (s *Sandbox) executeWithInterp(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	s.mu.RLock()
	useOSSandbox := s.osSandbox
	pool := s.pool
	s.mu.RUnlock()

	var out bytes.Buffer

	// Build interpreter options
	opts := []interp.RunnerOption{
		interp.Dir(workDir),
		interp.StdIO(nil, &out, &out),
		interp.Env(expand.ListEnviron(os.Environ()...)),
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			hc := interp.HandlerCtx(ctx)
			if err := validateExpandedPaths(args, hc.Dir, readAllowedPaths, writeAllowedPaths); err != nil {
				return nil, err
			}
			return args, nil
		}),
		interp.OpenHandler(func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			hc := interp.HandlerCtx(ctx)
			if err := validateOpenPath(path, flag, hc.Dir, readAllowedPaths, writeAllowedPaths); err != nil {
				return nil, err
			}
			return interp.DefaultOpenHandler()(ctx, path, flag, perm)
		}),
	}

	// If OS sandbox enabled, use custom ExecHandler to delegate to worker
	if useOSSandbox && pool != nil {
		opts = append(opts, interp.ExecHandler(func(ctx context.Context, args []string) error {
			return s.execInWorker(ctx, args, pool)
		}))
	}

	runner, err := interp.New(opts...)
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

// execInWorker sends a command to the worker pool for execution in bwrap.
func (s *Sandbox) execInWorker(ctx context.Context, args []string, pool *os_sandbox.WorkerPool) error {
	w, err := pool.Acquire()
	if err != nil {
		return fmt.Errorf("failed to acquire worker: %w", err)
	}
	defer pool.Release(w)

	hc := interp.HandlerCtx(ctx)

	// Read stdin if available
	var stdinData []byte
	if hc.Stdin != nil {
		stdinData, _ = io.ReadAll(hc.Stdin)
	}

	// Convert environment
	envMap := make(map[string]string)
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if !vr.IsSet() {
			return true
		}
		envMap[name] = vr.String()
		return true
	})

	req := os_sandbox.WorkerRequest{
		Args:      args,
		Dir:       hc.Dir,
		Env:       envMap,
		StdinData: stdinData,
	}

	resp, err := w.Send(ctx, req)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}

	// Write captured output to parent's stdout/stderr
	if len(resp.Stdout) > 0 {
		hc.Stdout.Write(resp.Stdout)
	}
	if len(resp.Stderr) > 0 {
		hc.Stderr.Write(resp.Stderr)
	}

	if resp.ExitCode != 0 {
		return interp.ExitStatus(resp.ExitCode)
	}

	return nil
}
