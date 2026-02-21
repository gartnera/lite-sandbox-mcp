package bash_sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Sandbox executes bash commands after parsing and validating them against
// the built-in allowlist plus any extra commands from config.
type Sandbox struct {
	mu               sync.RWMutex
	cfg              *config.Config
	extraCommands    map[string]bool
	imdsEndpoint     string
	runtimeReadPaths []string
	osSandbox        bool
	worker           *os_sandbox.Worker
	workerWorkDir    string
	workerRuntimeBinds []string
	workerBlockAWS   bool
	// argValidators holds a reference to commandArgValidators so that
	// validateSubCommand can look up per-command validators at runtime
	// without creating a package-level initialization cycle.
	argValidators map[string]func(s *Sandbox, args []*syntax.Word) error
}

// NewSandbox creates a Sandbox with no extra commands.
func NewSandbox() *Sandbox {
	return &Sandbox{
		cfg:           &config.Config{},
		argValidators: commandArgValidators,
	}
}

// UpdateConfig replaces the sandbox configuration with the provided config.
func (s *Sandbox) UpdateConfig(cfg *config.Config, workDir string) {
	m := make(map[string]bool, len(cfg.ExtraCommands))
	for _, c := range cfg.ExtraCommands {
		m[c] = true
	}
	// Detect runtime paths for read-only access (e.g., GOPATH, GOCACHE, pnpm store)
	runtimeReadPaths := detectRuntimeBinds(cfg.Runtimes)

	// Determine if AWS credentials should be blocked
	blockAWSCredentials := shouldBlockAWSCredentials(cfg.AWS)

	s.mu.Lock()
	s.cfg = cfg
	s.extraCommands = m
	s.runtimeReadPaths = runtimeReadPaths

	// Store worker config for lazy start / restart.
	s.workerWorkDir = workDir
	s.workerRuntimeBinds = runtimeReadPaths
	s.workerBlockAWS = blockAWSCredentials

	// Handle OS sandbox enable/disable
	newOSSandbox := cfg.OSSandboxEnabled()
	if newOSSandbox != s.osSandbox {
		// OS sandbox setting changed
		if s.worker != nil {
			slog.Info("closing existing worker")
			s.worker.Close()
			s.worker = nil
		}
		if newOSSandbox {
			slog.Info("enabling OS sandbox", "block_aws_credentials", blockAWSCredentials)
		}
		s.osSandbox = newOSSandbox
	}
	s.mu.Unlock()
}

// shouldBlockAWSCredentials determines if ~/.aws/ should be blocked.
// Returns true if AWS is configured to use IMDS (force_profile set).
// Returns false if AWS allows raw credentials or is not configured.
// Note: ~/.ssh/ is ALWAYS blocked regardless of this setting.
func shouldBlockAWSCredentials(awsCfg *config.AWSConfig) bool {
	if awsCfg == nil {
		return false
	}
	// Block AWS credentials only when using IMDS (force_profile is set)
	return awsCfg.UsesIMDS()
}

// getConfig returns a snapshot of the current config.
func (s *Sandbox) getConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// getExtraCommands returns a snapshot of the current extra commands.
func (s *Sandbox) getExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraCommands
}

// SetIMDSEndpoint sets the IMDS endpoint URL for AWS credential fetching.
func (s *Sandbox) SetIMDSEndpoint(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imdsEndpoint = endpoint
}

// RuntimeReadPaths returns the detected runtime paths that should be
// readable (but not writable) by sandboxed commands. These include paths
// like GOPATH, GOCACHE, and pnpm store directories.
func (s *Sandbox) RuntimeReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimeReadPaths
}

// ConfigReadPaths returns the user-configured readable paths (with ~ expanded).
func (s *Sandbox) ConfigReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedReadablePaths()
}

// ConfigWritePaths returns the user-configured writable paths (with ~ expanded).
func (s *Sandbox) ConfigWritePaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedWritablePaths()
}

// Close shuts down the sandbox, closing the worker if running.
func (s *Sandbox) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.worker != nil {
		return s.worker.Close()
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
					if !s.getConfig().LocalBinaryExecution.IsEnabled() || !isScriptPath(cmdName) {
						validationErr = fmt.Errorf("command %q is not allowed", cmdName)
						return false
					}
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

// ValidateCommand parses and validates a bash command without executing it.
// It mirrors the validation in Execute() but skips execution.
// workDir is the working directory for resolving relative paths.
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
func (s *Sandbox) ValidateCommand(command string, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	f, err := ParseBash(command)
	if err != nil {
		return err
	}
	if err := s.validate(f); err != nil {
		return err
	}
	if err := validatePaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return err
	}
	if err := validateRedirectPaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return err
	}
	return nil
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
// If OS sandbox is enabled, ExecHandler delegates to the worker.
func (s *Sandbox) executeWithInterp(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	s.mu.RLock()
	useOSSandbox := s.osSandbox
	imdsEndpoint := s.imdsEndpoint
	s.mu.RUnlock()

	var out bytes.Buffer

	// Build environment with IMDS endpoint if AWS is enabled
	// IMPORTANT: Set as actual environment variable so subprocesses (like aws cli) can see it
	env := os.Environ()
	if imdsEndpoint != "" {
		envVar := fmt.Sprintf("AWS_EC2_METADATA_SERVICE_ENDPOINT=%s", imdsEndpoint)
		env = append(env, envVar)
		// Also set in actual process environment so it's visible in shell sessions
		os.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsEndpoint)
	}

	// Store sandbox paths in context so nested bash/sh can access them
	ctx = context.WithValue(ctx, sandboxPathsKey, &sandboxPaths{
		readAllowedPaths:  readAllowedPaths,
		writeAllowedPaths: writeAllowedPaths,
	})

	// Build interpreter options
	opts := []interp.RunnerOption{
		interp.Dir(workDir),
		interp.StdIO(nil, &out, &out),
		interp.Env(expand.ListEnviron(env...)),
	}

	// Add security handlers (CallHandler, OpenHandler, ExecHandler)
	opts = append(opts, s.buildSecurityHandlers(readAllowedPaths, writeAllowedPaths, useOSSandbox)...)

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

// execInWorker sends a command to the worker for execution in the OS sandbox.
func (s *Sandbox) execInWorker(ctx context.Context, args []string) error {
	w, err := s.getOrCreateWorker()
	if err != nil {
		return fmt.Errorf("failed to get worker: %w", err)
	}

	hc := interp.HandlerCtx(ctx)

	// Convert environment
	envMap := make(map[string]string)
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if !vr.IsSet() {
			return true
		}
		envMap[name] = vr.String()
		return true
	})

	exitCode, err := w.Exec(ctx, args, hc.Dir, envMap, hc.Stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}

	if exitCode != 0 {
		return interp.ExitStatus(exitCode)
	}

	return nil
}

// getOrCreateWorker returns the current worker, starting a new one if the worker
// is nil or dead. Must be called without holding s.mu.
func (s *Sandbox) getOrCreateWorker() (*os_sandbox.Worker, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.worker != nil && !s.worker.IsDead() {
		return s.worker, nil
	}

	slog.Info("starting new sandbox worker", "workDir", s.workerWorkDir, "blockAWS", s.workerBlockAWS)
	w, err := os_sandbox.StartWorker(context.Background(), s.workerWorkDir, s.workerRuntimeBinds, s.workerBlockAWS)
	if err != nil {
		return nil, fmt.Errorf("failed to start worker: %w", err)
	}
	s.worker = w
	return w, nil
}
