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
// It reads HostMsg messages from stdin and streams stdout/stderr WorkerMsg messages back.
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

	for {
		var msg HostMsg
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil // host closed connection — clean shutdown
			}
			slog.Error("failed to decode host message", "error", err)
			return fmt.Errorf("failed to decode host message: %w", err)
		}

		if msg.Type != HostMsgExec {
			return fmt.Errorf("expected HostMsgExec, got type %d", msg.Type)
		}

		slog.Info("executing command", "args", msg.Args, "dir", msg.Dir)

		if err := streamCommand(enc, dec, msg); err != nil {
			return err
		}
	}
}

// streamCommand starts the command described by req, streams stdin from the decoder,
// and streams stdout/stderr back via the encoder. Sends WorkerMsgDone when finished.
func streamCommand(enc *lockedEncoder, dec *gob.Decoder, req HostMsg) error {
	if len(req.Args) == 0 {
		return enc.send(WorkerMsg{Type: WorkerMsgDone, ExitCode: 1, Error: "no command specified"})
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

	// Wire stdin through an io.Pipe so the decoder goroutine can feed it.
	pr, pw := io.Pipe()
	cmd.Stdin = pr

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		pr.Close()
		pw.Close()
		return enc.send(WorkerMsg{Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stdout pipe: " + err.Error()})
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		pr.Close()
		pw.Close()
		return enc.send(WorkerMsg{Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stderr pipe: " + err.Error()})
	}

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return enc.send(WorkerMsg{Type: WorkerMsgDone, ExitCode: 1, Error: "failed to start command: " + err.Error()})
	}

	var wg sync.WaitGroup

	// Goroutine 1: receive stdin chunks from host decoder and write to command's stdin pipe.
	// This is the only consumer of dec until HostMsgStdinEOF is received.
	// RunWorker will not call dec.Decode again until streamCommand returns (after wg.Wait).
	wg.Go(func() {
		defer pw.Close()
		for {
			var stdinMsg HostMsg
			if err := dec.Decode(&stdinMsg); err != nil {
				slog.Error("failed to decode stdin message", "error", err)
				return
			}
			switch stdinMsg.Type {
			case HostMsgStdin:
				if len(stdinMsg.Data) > 0 {
					if _, err := pw.Write(stdinMsg.Data); err != nil {
						// Command closed stdin early (e.g. head -1) — that's fine
						return
					}
				}
			case HostMsgStdinEOF:
				return // pw closed via defer
			default:
				slog.Error("unexpected message type while reading stdin", "type", stdinMsg.Type)
				return
			}
		}
	})

	// Goroutine 2: stream stdout chunks to host.
	wg.Go(func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if encErr := enc.send(WorkerMsg{Type: WorkerMsgStdout, Data: chunk}); encErr != nil {
					slog.Error("failed to send stdout chunk", "error", encErr)
					return
				}
			}
			if err != nil {
				return
			}
		}
	})

	// Goroutine 3: stream stderr chunks to host.
	wg.Go(func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if encErr := enc.send(WorkerMsg{Type: WorkerMsgStderr, Data: chunk}); encErr != nil {
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

	return enc.send(WorkerMsg{Type: WorkerMsgDone, ExitCode: exitCode, Error: errStr})
}
