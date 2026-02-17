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

// HostMsgType identifies messages sent from host to worker.
type HostMsgType int

const (
	HostMsgExec     HostMsgType = iota // Start a command (Args, Dir, Env)
	HostMsgStdin                       // Stdin data chunk (Data)
	HostMsgStdinEOF                    // No more stdin
)

// HostMsg is a message sent from the MCP server to a worker process.
type HostMsg struct {
	Type HostMsgType
	Args []string          // For HostMsgExec
	Dir  string            // For HostMsgExec
	Env  map[string]string // For HostMsgExec
	Data []byte            // For HostMsgStdin
}

// WorkerMsgType identifies messages sent from worker to host.
type WorkerMsgType int

const (
	WorkerMsgReady  WorkerMsgType = iota // Worker ready (startup signal)
	WorkerMsgStdout                      // Stdout data chunk (Data)
	WorkerMsgStderr                      // Stderr data chunk (Data)
	WorkerMsgDone                        // Command finished (ExitCode, Error)
)

// WorkerMsg is a message sent from a worker process back to the MCP server.
type WorkerMsg struct {
	Type     WorkerMsgType
	Data     []byte
	ExitCode int
	Error    string
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
// blockAWSCredentials specifies whether to block ~/.aws directory.
// Note: ~/.ssh is ALWAYS blocked regardless of this parameter.
func StartWorker(ctx context.Context, workDir string, extraBinds []string, blockAWSCredentials bool) (*Worker, error) {
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
			// Always block ~/.ssh
			sshDir := filepath.Join(homeDir, ".ssh")
			if _, err := os.Stat(sshDir); err == nil {
				args = append(args, "--tmpfs", sshDir)
			}

			// Conditionally block ~/.aws
			if blockAWSCredentials {
				awsDir := filepath.Join(homeDir, ".aws")
				if _, err := os.Stat(awsDir); err == nil {
					args = append(args, "--tmpfs", awsDir)
				}
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
		profile := generateSBPLProfile(realWorkDir, extraBinds, blockAWSCredentials)

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

	// Wait for ready signal from worker
	var ready WorkerMsg
	if err := w.dec.Decode(&ready); err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to receive ready signal: %w", err)
	}
	if ready.Type != WorkerMsgReady {
		w.Close()
		return nil, fmt.Errorf("expected ready signal, got type %d", ready.Type)
	}

	slog.InfoContext(ctx, "worker ready", "pid", cmd.Process.Pid)

	return w, nil
}

// generateSBPLProfile generates a Scheme-based sandbox profile for macOS sandbox-exec.
// The profile allows read-only access to the entire filesystem, but restricts writes
// to specific directories (workDir, extraBinds, and system temp directories).
// blockAWSCredentials controls whether ~/.aws is blocked.
// Note: ~/.ssh is ALWAYS blocked regardless of blockAWSCredentials.
func generateSBPLProfile(workDir string, extraBinds []string, blockAWSCredentials bool) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")

	// Get home directory for credential blocking
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fall back to not blocking if we can't get home dir
		slog.Warn("failed to get home directory for SBPL profile", "error", err)
		return sb.String()
	}

	// Deny access to credential directories (must come after allow default)
	// Always block ~/.ssh
	sshDir := filepath.Join(homeDir, ".ssh")
	sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"%s\"))\n", sshDir))

	// Conditionally block ~/.aws
	if blockAWSCredentials {
		awsDir := filepath.Join(homeDir, ".aws")
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"%s\"))\n", awsDir))
	}

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

// Exec runs a command in the worker, streaming stdin/stdout/stderr.
// stdin, stdout, stderr may be nil.
// Returns the command exit code and any protocol error.
func (w *Worker) Exec(ctx context.Context, args []string, dir string, env map[string]string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	w.mu.Lock()
	if w.dead {
		w.mu.Unlock()
		return 1, fmt.Errorf("worker is dead")
	}
	if w.cmd.ProcessState != nil {
		w.dead = true
		w.mu.Unlock()
		return 1, fmt.Errorf("worker process has exited")
	}

	slog.DebugContext(ctx, "sending exec to worker", "args", args)

	// Send exec message while holding the lock to prevent concurrent Exec calls.
	if err := w.enc.Encode(HostMsg{Type: HostMsgExec, Args: args, Dir: dir, Env: env}); err != nil {
		w.dead = true
		w.mu.Unlock()
		return 1, fmt.Errorf("failed to send exec: %w", err)
	}
	if err := w.bufStdin.Flush(); err != nil {
		w.dead = true
		w.mu.Unlock()
		return 1, fmt.Errorf("failed to flush exec: %w", err)
	}
	w.mu.Unlock()

	// Pump stdin in a background goroutine; pumpStdin is the only writer after this point.
	stdinDone := make(chan error, 1)
	go func() {
		stdinDone <- w.pumpStdin(stdin)
	}()

	// Read stdout/stderr/done messages until command finishes.
	exitCode, execErr := w.readWorkerOutput(stdout, stderr)

	// Wait for stdin pump.
	if pumpErr := <-stdinDone; pumpErr != nil && execErr == nil {
		execErr = pumpErr
	}

	if execErr != nil {
		w.mu.Lock()
		w.dead = true
		w.mu.Unlock()
	}

	return exitCode, execErr
}

// pumpStdin reads from r in 4096-byte chunks and sends them to the worker,
// then sends HostMsgStdinEOF. If r is nil, only the EOF is sent.
func (w *Worker) pumpStdin(r io.Reader) error {
	if r != nil {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if encErr := w.enc.Encode(HostMsg{Type: HostMsgStdin, Data: chunk}); encErr != nil {
					return fmt.Errorf("failed to send stdin chunk: %w", encErr)
				}
				if flushErr := w.bufStdin.Flush(); flushErr != nil {
					return fmt.Errorf("failed to flush stdin chunk: %w", flushErr)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("stdin read error: %w", err)
			}
		}
	}
	if err := w.enc.Encode(HostMsg{Type: HostMsgStdinEOF}); err != nil {
		return fmt.Errorf("failed to send stdin EOF: %w", err)
	}
	return w.bufStdin.Flush()
}

// readWorkerOutput reads WorkerMsg messages until WorkerMsgDone,
// writing stdout/stderr chunks to the provided writers.
func (w *Worker) readWorkerOutput(stdout, stderr io.Writer) (int, error) {
	for {
		var msg WorkerMsg
		if err := w.dec.Decode(&msg); err != nil {
			return 1, fmt.Errorf("failed to decode worker message: %w", err)
		}
		switch msg.Type {
		case WorkerMsgStdout:
			if stdout != nil && len(msg.Data) > 0 {
				stdout.Write(msg.Data) //nolint:errcheck
			}
		case WorkerMsgStderr:
			if stderr != nil && len(msg.Data) > 0 {
				stderr.Write(msg.Data) //nolint:errcheck
			}
		case WorkerMsgDone:
			var err error
			if msg.Error != "" {
				err = fmt.Errorf("%s", msg.Error)
			}
			return msg.ExitCode, err
		default:
			return 1, fmt.Errorf("unexpected worker message type: %d", msg.Type)
		}
	}
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
	size                int
	workDir             string
	runtimeBinds        []string // Additional bind mounts for runtime paths (Go, etc.)
	blockAWSCredentials bool     // Whether to block ~/.aws directory (always blocks ~/.ssh)
	workers             chan *Worker
	mu                  sync.Mutex
	started             int
	ctx                 context.Context
	cancel              context.CancelFunc
	closeOnce           sync.Once
}

// NewWorkerPool creates a new worker pool with the specified size.
// Workers are created lazily on demand.
// extraBinds specifies additional writable paths to bind mount (e.g., for runtimes).
// blockAWSCredentials specifies whether to block ~/.aws directory.
// Note: ~/.ssh is ALWAYS blocked regardless of this parameter.
func NewWorkerPool(size int, workDir string, extraBinds []string, blockAWSCredentials bool) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		size:                size,
		workDir:             workDir,
		runtimeBinds:        extraBinds,
		blockAWSCredentials: blockAWSCredentials,
		workers:             make(chan *Worker, size),
		ctx:                 ctx,
		cancel:              cancel,
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
	w, err := StartWorker(p.ctx, p.workDir, p.runtimeBinds, p.blockAWSCredentials)
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
