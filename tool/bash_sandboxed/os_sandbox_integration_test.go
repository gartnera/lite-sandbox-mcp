package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox-mcp/config"
)

// TestOSSandboxBasicExecution tests that OS sandbox can execute basic commands.
func TestOSSandboxBasicExecution(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	s := NewSandbox()

	// Enable OS sandbox
	enabled := true
	workers := 2
	cfg := &config.Config{
		OSSandbox:        &enabled,
		OSSandboxWorkers: &workers,
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Test basic command
	output, err := s.Execute(context.Background(), "echo hello", tmpDir, []string{tmpDir})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if output != "hello\n" {
		t.Errorf("unexpected output: got %q, want %q", output, "hello\n")
	}
}

// TestOSSandboxFileIsolation tests that OS sandbox provides read-only root.
func TestOSSandboxFileIsolation(t *testing.T) {
	tmpDir := t.TempDir()

	s := NewSandbox()

	enabled := true
	cfg := &config.Config{
		OSSandbox: &enabled,
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Try to write outside workdir - should fail
	output, err := s.Execute(context.Background(), "touch /root/testfile", tmpDir, []string{tmpDir})
	if err == nil {
		t.Errorf("expected error when writing to /root, got success. output: %s", output)
	}

	// Try to write inside workdir - should succeed
	testFile := filepath.Join(tmpDir, "testfile")
	_, err = s.Execute(context.Background(), "touch "+testFile, tmpDir, []string{tmpDir})
	if err != nil {
		t.Errorf("expected success when writing to workdir, got error: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("expected file to exist in workdir")
	}
}

// TestOSSandboxWorkerPool tests that multiple workers can execute concurrently.
func TestOSSandboxWorkerPool(t *testing.T) {
	tmpDir := t.TempDir()

	s := NewSandbox()

	enabled := true
	workers := 3
	cfg := &config.Config{
		OSSandbox:        &enabled,
		OSSandboxWorkers: &workers,
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Execute multiple commands concurrently
	type result struct {
		output string
		err    error
	}
	results := make(chan result, 5)

	for i := 0; i < 5; i++ {
		go func(n int) {
			output, err := s.Execute(context.Background(), "echo test", tmpDir, []string{tmpDir})
			results <- result{output, err}
		}(i)
	}

	// Collect results
	for i := 0; i < 5; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("concurrent execute %d failed: %v", i, r.err)
		}
		if r.output != "test\n" {
			t.Errorf("concurrent execute %d unexpected output: got %q, want %q", i, r.output, "test\n")
		}
	}
}
