package os_sandbox

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
)

// lockedEncoder wraps a gob.Encoder with a mutex and buffered writer for concurrent use.
type lockedEncoder struct {
	mu  sync.Mutex
	buf *bufio.Writer
	enc *gob.Encoder
}

func newLockedEncoder(w io.Writer) *lockedEncoder {
	buf := bufio.NewWriter(w)
	return &lockedEncoder{
		buf: buf,
		enc: gob.NewEncoder(buf),
	}
}

func (le *lockedEncoder) send(msg WorkerMsg) error {
	le.mu.Lock()
	defer le.mu.Unlock()
	if err := le.enc.Encode(msg); err != nil {
		return err
	}
	return le.buf.Flush()
}

// RunWorker is the main loop for a sandbox worker process (runs inside bwrap/sandbox-exec).
// It reads HostMsg messages from stdin and dispatches them to concurrent executions.
// Multiple executions may be in flight simultaneously, identified by their ID.
// This is called by the "sandbox-worker" CLI command.
func RunWorker() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	slog.Info("sandbox worker started")

	enc := newLockedEncoder(os.Stdout)
	dec := gob.NewDecoder(os.Stdin)

	// Send ready signal
	slog.Info("sending ready signal")
	if err := enc.send(WorkerMsg{Type: WorkerMsgReady}); err != nil {
		return fmt.Errorf("failed to send ready signal: %w", err)
	}

	// stdinPipes maps execution ID to the pipe writer feeding that execution's stdin.
	stdinPipes := make(map[uint64]*io.PipeWriter)
	var stdinMu sync.Mutex

	for {
		var msg HostMsg
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil // host closed connection — clean shutdown
			}
			slog.Error("failed to decode host message", "error", err)
			return fmt.Errorf("failed to decode host message: %w", err)
		}

		switch msg.Type {
		case HostMsgExec:
			slog.Info("executing command", "args", msg.Args, "dir", msg.Dir, "id", msg.ID)
			pr, pw := io.Pipe()
			stdinMu.Lock()
			stdinPipes[msg.ID] = pw
			stdinMu.Unlock()
			go func(m HostMsg, stdinReader io.Reader) {
				if err := streamCommand(enc, m.ID, m, stdinReader); err != nil {
					slog.Error("streamCommand error", "id", m.ID, "error", err)
				}
				// Clean up: close and remove the pipe writer if still present.
				stdinMu.Lock()
				if pw, ok := stdinPipes[m.ID]; ok {
					pw.Close()
					delete(stdinPipes, m.ID)
				}
				stdinMu.Unlock()
			}(msg, pr)

		case HostMsgStdin:
			stdinMu.Lock()
			pw, ok := stdinPipes[msg.ID]
			stdinMu.Unlock()
			if ok && len(msg.Data) > 0 {
				pw.Write(msg.Data) // ignore error; command may have closed stdin early
			}

		case HostMsgStdinEOF:
			stdinMu.Lock()
			pw, ok := stdinPipes[msg.ID]
			if ok {
				delete(stdinPipes, msg.ID)
			}
			stdinMu.Unlock()
			if ok {
				pw.Close()
			}

		default:
			slog.Error("unexpected message type", "type", msg.Type)
			return fmt.Errorf("unexpected message type %d", msg.Type)
		}
	}
}

// streamCommand starts the command described by req, uses stdinReader for its stdin,
// and streams stdout/stderr back via the encoder. Sends WorkerMsgDone when finished.
// The id parameter is included in all outgoing WorkerMsg messages for multiplexing.
func streamCommand(enc *lockedEncoder, id uint64, req HostMsg, stdinReader io.Reader) error {
	if len(req.Args) == 0 {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "no command specified"})
	}

	cmd := exec.Command(req.Args[0], req.Args[1:]...)
	cmd.Dir = req.Dir

	if len(req.Env) > 0 {
		env := make([]string, 0, len(req.Env))
		for k, v := range req.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	cmd.Stdin = stdinReader

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stdout pipe: " + err.Error()})
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stderr pipe: " + err.Error()})
	}

	if err := cmd.Start(); err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to start command: " + err.Error()})
	}

	var wg sync.WaitGroup

	// Goroutine 1: stream stdout chunks to host.
	wg.Go(func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if encErr := enc.send(WorkerMsg{ID: id, Type: WorkerMsgStdout, Data: chunk}); encErr != nil {
					slog.Error("failed to send stdout chunk", "error", encErr)
					return
				}
			}
			if err != nil {
				return
			}
		}
	})

	// Goroutine 2: stream stderr chunks to host.
	wg.Go(func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if encErr := enc.send(WorkerMsg{ID: id, Type: WorkerMsgStderr, Data: chunk}); encErr != nil {
					slog.Error("failed to send stderr chunk", "error", encErr)
					return
				}
			}
			if err != nil {
				return
			}
		}
	})

	// Wait for all I/O goroutines to complete, then collect the exit status.
	wg.Wait()

	exitCode := 0
	errStr := ""
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
			errStr = err.Error()
		}
	}

	return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: exitCode, Error: errStr})
}
