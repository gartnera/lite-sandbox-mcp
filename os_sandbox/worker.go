package os_sandbox

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
)

// RunWorker is the main loop for a sandbox worker process (runs inside bwrap).
// It reads gob-encoded WorkerRequest messages from stdin, executes individual commands,
// and writes gob-encoded WorkerResponse messages to stdout.
// This is called by the "sandbox-worker" CLI command.
func RunWorker() error {
	// Ensure slog writes to stderr, not stdout (stdout is for gob)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	slog.Info("sandbox worker started")

	enc := gob.NewEncoder(os.Stdout)
	dec := gob.NewDecoder(os.Stdin)

	// Send ready signal (empty response) to indicate worker is initialized
	slog.Info("sending ready signal")
	if err := enc.Encode(WorkerResponse{}); err != nil {
		return fmt.Errorf("failed to send ready signal: %w", err)
	}

	for {
		var req WorkerRequest
		if err := dec.Decode(&req); err != nil {
			slog.Error("failed to decode request", "error", err)
			return fmt.Errorf("failed to decode request: %w", err)
		}

		slog.Info("executing command", "args", req.Args, "dir", req.Dir)

		// Execute the command directly
		resp := executeCommand(req)

		// Send response
		if err := enc.Encode(resp); err != nil {
			slog.Error("failed to encode response", "error", err)
			return fmt.Errorf("failed to encode response: %w", err)
		}
	}
}

// executeCommand executes a single command inside the worker.
func executeCommand(req WorkerRequest) WorkerResponse {
	if len(req.Args) == 0 {
		return WorkerResponse{
			ExitCode: 1,
			Error:    "no command specified",
		}
	}

	cmd := exec.Command(req.Args[0], req.Args[1:]...)
	cmd.Dir = req.Dir

	// Set environment
	if len(req.Env) > 0 {
		env := make([]string, 0, len(req.Env))
		for k, v := range req.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	// Setup stdin
	if len(req.StdinData) > 0 {
		cmd.Stdin = bytes.NewReader(req.StdinData)
	}

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute
	err := cmd.Run()

	resp := WorkerResponse{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			resp.ExitCode = exitErr.ExitCode()
		} else {
			resp.ExitCode = 1
			resp.Error = err.Error()
		}
	}

	return resp
}
