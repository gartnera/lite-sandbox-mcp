package os_sandbox

import (
	"bufio"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// WorkerRequest is sent from the MCP server to a worker process over stdin (gob).
// The worker executes a single command (from interp.ExecHandler).
type WorkerRequest struct {
	Args      []string          // Command and arguments (e.g., ["ls", "-la"])
	Dir       string            // Working directory
	Env       map[string]string // Environment variables
	StdinData []byte            // Data to send to command's stdin
}

// WorkerResponse is sent from a worker process back to the MCP server over stdout (gob).
type WorkerResponse struct {
	Stdout   []byte // Command's stdout
	Stderr   []byte // Command's stderr
	ExitCode int    // Command exit code
	Error    string // Error message if communication/setup failed
}

// Worker manages a single bwrap sandbox process communicating via gob over stdin/stdout.
type Worker struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	bufStdin  *bufio.Writer
	enc       *gob.Encoder
	dec       *gob.Decoder
	mu        sync.Mutex
	dead      bool
}

// StartWorker starts a new sandbox worker process.
// The worker runs the "lite-sandbox sandbox-worker" subcommand inside a platform-specific sandbox.
// On Linux, this uses bwrap. On macOS, this uses sandbox-exec with SBPL profiles.
// extraBinds specifies additional writable paths to bind mount (e.g., for runtimes).
func StartWorker(ctx context.Context, workDir string, extraBinds []string) (*Worker, error) {
	// Find our own binary path to pass to the sandbox
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// If running from a test binary, try to find the actual binary
	baseName := filepath.Base(self)
	if baseName != "lite-sandbox" && (filepath.Ext(self) == ".test" || filepath.Ext(baseName) == ".test") {
		// Try to find lite-sandbox in current working directory
		cwd, err := os.Getwd()
		if err == nil {
			candidatePath := filepath.Join(cwd, "lite-sandbox")
			if _, err := os.Stat(candidatePath); err == nil {
				self = candidatePath
			} else {
				// Try two levels up (for tests in tool/bash_sandboxed)
				candidatePath = filepath.Join(cwd, "../..", "lite-sandbox")
				if absPath, err := filepath.Abs(candidatePath); err == nil {
					if _, err := os.Stat(absPath); err == nil {
						self = absPath
					}
				}
			}
		}
	}

	// Resolve symlinks in workDir (e.g., /tmp might be a symlink)
	realWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workDir symlinks: %w", err)
	}

	// Ensure workDir exists
	if err := os.MkdirAll(realWorkDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workDir: %w", err)
	}

	slog.InfoContext(ctx, "starting worker", "binary", self, "workDir", realWorkDir, "platform", runtime.GOOS)

	// Platform-specific sandbox command setup
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// Build bwrap command
		// Strategy: bind root read-only, add writable tmpfs for /tmp, add runtime binds, then rebind workDir as writable
		// The order matters: later mounts can override earlier ones, so workDir bind comes last
		// and will override the tmpfs if workDir is under /tmp (e.g., in tests)
		// --ro-bind / / : read-only root filesystem
		// --tmpfs /tmp : writable /tmp (needed by Go and other tools for build cache)
		// --tmpfs <credential-dir> : empty overlay to block credential access
		// --bind <runtime-path> <runtime-path> : writable runtime directories (GOPATH, etc.)
		// --bind <cwd> <cwd> : writable current working directory (overrides tmpfs if under /tmp)
		// --dev /dev : fresh devtmpfs
		// --proc /proc : fresh procfs
		// --unshare-all --share-net : unshare everything except network
		// --die-with-parent : kill worker if parent dies
		// --chdir <cwd> : start in working directory
		args := []string{
			"--ro-bind", "/", "/",
			"--tmpfs", "/tmp",
		}

		// Block credential directories with empty tmpfs overlays
		homeDir, err := os.UserHomeDir()
		if err == nil {
			awsDir := filepath.Join(homeDir, ".aws")
			sshDir := filepath.Join(homeDir, ".ssh")
			// Only add tmpfs if directory exists (bwrap fails if we try to mount over non-existent path)
			if _, err := os.Stat(awsDir); err == nil {
				args = append(args, "--tmpfs", awsDir)
			}
			if _, err := os.Stat(sshDir); err == nil {
				args = append(args, "--tmpfs", sshDir)
			}
		}

		// Add runtime bind mounts (e.g., GOPATH for Go runtime)
		for _, path := range extraBinds {
			// Create the directory if it doesn't exist
			if err := os.MkdirAll(path, 0755); err != nil {
				slog.WarnContext(ctx, "failed to create runtime bind path", "path", path, "error", err)
				continue
			}
			args = append(args, "--bind", path, path)
		}

		// Add workDir bind and remaining args
		args = append(args,
			"--bind", realWorkDir, realWorkDir,
			"--dev", "/dev",
			"--proc", "/proc",
			"--unshare-all",
			"--share-net",
			"--die-with-parent",
			"--chdir", realWorkDir,
			"--",
			self, "sandbox-worker",
		)

		cmd = exec.CommandContext(ctx, "bwrap", args...)

	case "darwin":
		// Build sandbox-exec command
		// Generate SBPL profile that allows read-only root and writable workDir + extraBinds
		profile := generateSBPLProfile(realWorkDir, extraBinds)

		// sandbox-exec -p <profile> <binary> <args>
		cmd = exec.CommandContext(ctx, "sandbox-exec", "-p", profile, self, "sandbox-worker")
		cmd.Dir = realWorkDir

	default:
		return nil, fmt.Errorf("os sandbox not supported on %s", runtime.GOOS)
	}

	cmd.Stderr = os.Stderr // Pass through stderr for worker logs

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to start sandbox: %w", err)
	}

	slog.InfoContext(ctx, "started sandbox worker", "platform", runtime.GOOS, "pid", cmd.Process.Pid)

	// Use buffered I/O for gob streams
	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)

	w := &Worker{
		cmd:      cmd,
		stdin:    stdin,
		stdout:   stdout,
		bufStdin: bufStdin,
		enc:      gob.NewEncoder(bufStdin),
		dec:      gob.NewDecoder(bufStdout),
	}

	// Wait for ready signal from worker (just an empty response)
	var ready WorkerResponse
	if err := w.dec.Decode(&ready); err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to receive ready signal: %w", err)
	}

	slog.InfoContext(ctx, "worker ready", "pid", cmd.Process.Pid)

	return w, nil
}

// generateSBPLProfile generates a Scheme-based sandbox profile for macOS sandbox-exec.
// The profile allows read-only access to the entire filesystem, but restricts writes
// to specific directories (workDir, extraBinds, and system temp directories).
func generateSBPLProfile(workDir string, extraBinds []string) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")

	// Deny access to credential directories (must come before allow rules)
	// Block entire .aws and .ssh directories to prevent credential access
	sb.WriteString("(deny file-read* (regex #\"^/Users/[^/]+/\\.aws/\"))\n")
	sb.WriteString("(deny file-read* (regex #\"^/Users/[^/]+/\\.ssh/\"))\n")

	// Allow read access to entire filesystem (except denied paths above)
	sb.WriteString("(allow file-read* (subpath \"/\"))\n")

	// Allow write access to workDir and its resolved path
	sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", workDir))

	// If workDir is a symlink, also allow the resolved path
	if resolvedWorkDir, err := filepath.EvalSymlinks(workDir); err == nil && resolvedWorkDir != workDir {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", resolvedWorkDir))
	}

	// Allow write access to extra bind paths (e.g., GOPATH)
	for _, path := range extraBinds {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", path))
	}

	// Allow write access to system temp directories
	// /private/tmp is the canonical path, but allow both /tmp and /private/tmp
	sb.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/var/tmp\"))\n")

	// Allow write access to /var/folders (macOS user temp directories)
	// This is where TMPDIR points to on macOS and where Go creates build caches
	sb.WriteString("(allow file-write* (subpath \"/var/folders\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/var/folders\"))\n")

	// Allow write access to /dev for standard streams
	sb.WriteString("(allow file-write* (subpath \"/dev\"))\n")

	// Allow process execution
	sb.WriteString("(allow process-exec (subpath \"/\"))\n")
	sb.WriteString("(allow process-fork)\n")

	// Allow network access
	sb.WriteString("(allow network*)\n")

	// Allow mach lookups (required for macOS services)
	sb.WriteString("(allow mach-lookup)\n")

	// Allow signal operations
	sb.WriteString("(allow signal)\n")

	// Allow sysctl reads (required for many tools)
	sb.WriteString("(allow sysctl-read)\n")

	return sb.String()
}

// Send sends a request to the worker and waits for a response.
func (w *Worker) Send(ctx context.Context, req WorkerRequest) (WorkerResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dead {
		return WorkerResponse{}, fmt.Errorf("worker is dead")
	}

	// Check if process has exited
	if w.cmd.ProcessState != nil {
		w.dead = true
		return WorkerResponse{}, fmt.Errorf("worker process has exited")
	}

	slog.DebugContext(ctx, "sending request to worker", "args", req.Args)

	// Send request
	if err := w.enc.Encode(req); err != nil {
		w.dead = true
		return WorkerResponse{}, fmt.Errorf("failed to encode request: %w", err)
	}

	// Flush the buffer to ensure data is sent
	if err := w.bufStdin.Flush(); err != nil {
		w.dead = true
		return WorkerResponse{}, fmt.Errorf("failed to flush request: %w", err)
	}

	slog.DebugContext(ctx, "waiting for response from worker")

	// Read response
	var resp WorkerResponse
	if err := w.dec.Decode(&resp); err != nil {
		w.dead = true
		return WorkerResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}

	slog.DebugContext(ctx, "received response from worker", "stdout_len", len(resp.Stdout), "stderr_len", len(resp.Stderr), "exit_code", resp.ExitCode, "has_error", resp.Error != "")

	return resp, nil
}

// Close terminates the worker process.
func (w *Worker) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dead {
		return nil
	}

	w.dead = true
	w.stdin.Close()
	w.stdout.Close()

	if w.cmd.Process != nil {
		if err := w.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill worker: %w", err)
		}
		w.cmd.Wait() // Reap the process
	}

	return nil
}

// IsDead returns true if the worker is known to be dead.
func (w *Worker) IsDead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dead
}

// WorkerPool manages a pool of bwrap worker processes.
type WorkerPool struct {
	size         int
	workDir      string
	runtimeBinds []string // Additional bind mounts for runtime paths (Go, etc.)
	workers      chan *Worker
	mu           sync.Mutex
	started      int
	ctx          context.Context
	cancel       context.CancelFunc
	closeOnce    sync.Once
}

// NewWorkerPool creates a new worker pool with the specified size.
// Workers are created lazily on demand.
// extraBinds specifies additional writable paths to bind mount (e.g., for runtimes).
func NewWorkerPool(size int, workDir string, extraBinds []string) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		size:         size,
		workDir:      workDir,
		runtimeBinds: extraBinds,
		workers:      make(chan *Worker, size),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Acquire gets a worker from the pool, starting a new one if needed.
// If a dead worker is detected, it's replaced.
func (p *WorkerPool) Acquire() (*Worker, error) {
	select {
	case w := <-p.workers:
		// Got a worker from the pool, check if it's alive
		if w.IsDead() {
			slog.Info("worker is dead, starting replacement")
			return p.startNewWorker()
		}
		return w, nil
	default:
		// No workers available in the pool
		p.mu.Lock()
		if p.started < p.size {
			// We can start a new worker
			p.started++
			p.mu.Unlock()
			return p.startNewWorker()
		}
		p.mu.Unlock()

		// Pool is full, wait for a worker to be returned
		select {
		case <-p.ctx.Done():
			return nil, fmt.Errorf("worker pool closed")
		case w := <-p.workers:
			if w.IsDead() {
				slog.Info("worker is dead, starting replacement")
				return p.startNewWorker()
			}
			return w, nil
		}
	}
}

// startNewWorker starts a new worker process.
func (p *WorkerPool) startNewWorker() (*Worker, error) {
	w, err := StartWorker(p.ctx, p.workDir, p.runtimeBinds)
	if err != nil {
		// Decrement started count on failure
		p.mu.Lock()
		p.started--
		p.mu.Unlock()
		return nil, fmt.Errorf("failed to start worker: %w", err)
	}
	return w, nil
}

// Release returns a worker to the pool.
func (p *WorkerPool) Release(w *Worker) {
	if w.IsDead() {
		// Don't return dead workers to the pool
		p.mu.Lock()
		p.started--
		p.mu.Unlock()
		return
	}

	select {
	case p.workers <- w:
		// Successfully returned to pool
	case <-p.ctx.Done():
		// Pool is closed, kill the worker
		w.Close()
	}
}

// Close shuts down the worker pool and kills all workers.
func (p *WorkerPool) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()

		// Close the workers channel and kill all workers
		close(p.workers)
		for w := range p.workers {
			w.Close()
		}
	})
	return nil
}
