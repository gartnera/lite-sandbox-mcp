package os_sandbox

import (
	"bufio"
	"encoding/gob"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestWorkerIPCWithoutBwrap tests the gob IPC mechanism without bwrap.
func TestWorkerIPCWithoutBwrap(t *testing.T) {
	// Use the lite-sandbox-mcp binary (not the test binary)
	// Look in project root (two directories up from this test file)
	binary := "../lite-sandbox-mcp"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox-mcp binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	// Start worker directly (no bwrap)
	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	// Set up gob encoder/decoder with buffering
	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	t.Log("waiting for ready signal")
	var ready WorkerResponse
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("failed to receive ready signal: %v", err)
	}
	t.Log("received ready signal")

	// Send a simple command
	req := WorkerRequest{
		Args: []string{"echo", "hello"},
		Dir:  t.TempDir(),
		Env:  map[string]string{},
	}

	t.Log("sending command")
	if err := enc.Encode(req); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}
	if err := bufStdin.Flush(); err != nil {
		t.Fatalf("failed to flush request: %v", err)
	}

	// Read response with timeout
	t.Log("waiting for response")
	respChan := make(chan WorkerResponse, 1)
	errChan := make(chan error, 1)
	go func() {
		var resp WorkerResponse
		if err := dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	select {
	case resp := <-respChan:
		t.Logf("received response: stdout=%q, stderr=%q, exit_code=%d", resp.Stdout, resp.Stderr, resp.ExitCode)
		if resp.Error != "" {
			t.Fatalf("command failed: %s", resp.Error)
		}
		if resp.ExitCode != 0 {
			t.Fatalf("command exited with code %d", resp.ExitCode)
		}
		if string(resp.Stdout) != "hello\n" {
			t.Errorf("unexpected output: got %q, want %q", resp.Stdout, "hello\n")
		}
	case err := <-errChan:
		t.Fatalf("failed to decode response: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestWorkerIPCMultipleCommands tests sending multiple commands to the same worker.
func TestWorkerIPCMultipleCommands(t *testing.T) {
	binary := "../lite-sandbox-mcp"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox-mcp binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	var ready WorkerResponse
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("failed to receive ready signal: %v", err)
	}

	tmpDir := t.TempDir()

	// Send multiple commands
	testCases := []struct {
		args     []string
		expected string
	}{
		{[]string{"echo", "first"}, "first\n"},
		{[]string{"echo", "second"}, "second\n"},
		{[]string{"echo", "third"}, "third\n"},
	}

	for i, tc := range testCases {
		req := WorkerRequest{
			Args: tc.args,
			Dir:  tmpDir,
			Env:  map[string]string{},
		}

		if err := enc.Encode(req); err != nil {
			t.Fatalf("failed to encode request %d: %v", i, err)
		}
		if err := bufStdin.Flush(); err != nil {
			t.Fatalf("failed to flush request %d: %v", i, err)
		}

		var resp WorkerResponse
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("failed to decode response %d: %v", i, err)
		}

		if resp.Error != "" {
			t.Fatalf("command %d failed: %s", i, resp.Error)
		}
		if resp.ExitCode != 0 {
			t.Fatalf("command %d exited with code %d", i, resp.ExitCode)
		}
		if string(resp.Stdout) != tc.expected {
			t.Errorf("command %d: got %q, want %q", i, resp.Stdout, tc.expected)
		}
	}
}

// TestWorkerIPCWithBwrap tests the gob IPC mechanism WITH bwrap.
func TestWorkerIPCWithBwrap(t *testing.T) {
	binary := "../lite-sandbox-mcp"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox-mcp binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	// Get absolute path to binary
	absBinary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatalf("failed to get absolute path: %v", err)
	}

	tmpDir := t.TempDir()

	// Start worker with bwrap (same setup as StartWorker)
	args := []string{
		"--ro-bind", "/", "/",
		"--bind", tmpDir, tmpDir,
		"--dev", "/dev",
		"--proc", "/proc",
		"--unshare-all",
		"--share-net",
		"--die-with-parent",
		"--chdir", tmpDir,
		"--",
		absBinary, "sandbox-worker",
	}

	cmd := exec.Command("bwrap", args...)
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start bwrap worker: %v", err)
	}
	defer cmd.Process.Kill()

	t.Logf("started bwrap worker pid=%d", cmd.Process.Pid)

	// Set up gob encoder/decoder with buffering
	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	t.Log("waiting for ready signal")
	var ready WorkerResponse
	readyChan := make(chan error, 1)
	go func() {
		readyChan <- dec.Decode(&ready)
	}()

	select {
	case err := <-readyChan:
		if err != nil {
			t.Fatalf("failed to receive ready signal: %v", err)
		}
		t.Log("received ready signal")
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for ready signal")
	}

	// Send a simple command
	req := WorkerRequest{
		Args: []string{"echo", "hello"},
		Dir:  tmpDir,
		Env:  map[string]string{},
	}

	t.Log("sending command")
	if err := enc.Encode(req); err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}
	if err := bufStdin.Flush(); err != nil {
		t.Fatalf("failed to flush request: %v", err)
	}

	// Read response with timeout
	t.Log("waiting for response")
	respChan := make(chan WorkerResponse, 1)
	errChan := make(chan error, 1)
	go func() {
		var resp WorkerResponse
		if err := dec.Decode(&resp); err != nil {
			errChan <- err
			return
		}
		respChan <- resp
	}()

	select {
	case resp := <-respChan:
		t.Logf("received response: stdout=%q, stderr=%q, exit_code=%d", resp.Stdout, resp.Stderr, resp.ExitCode)
		if resp.Error != "" {
			t.Fatalf("command failed: %s", resp.Error)
		}
		if resp.ExitCode != 0 {
			t.Fatalf("command exited with code %d", resp.ExitCode)
		}
		if string(resp.Stdout) != "hello\n" {
			t.Errorf("unexpected output: got %q, want %q", resp.Stdout, "hello\n")
		}
	case err := <-errChan:
		t.Fatalf("failed to decode response: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}
