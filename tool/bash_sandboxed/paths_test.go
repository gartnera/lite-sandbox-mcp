package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRedirectPaths_Allowed(t *testing.T) {
	workDir := t.TempDir()
	os.WriteFile(filepath.Join(workDir, "input.txt"), []byte("hello"), 0o644)

	tests := []struct {
		name    string
		command string
	}{
		{"input redirect from local file", "cat < input.txt"},
		{"input redirect absolute allowed", "cat < " + workDir + "/input.txt"},
		{"heredoc no path", "cat <<EOF\nhello\nEOF"},
		{"output to /dev/null", "echo hello > /dev/null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validateRedirectPaths(f, workDir, []string{workDir}); err != nil {
				t.Fatalf("expected redirect path to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateRedirectPaths_Blocked(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"input redirect outside", "cat < /etc/passwd", "outside allowed directories"},
		{"input redirect traversal", "cat < ../../../etc/passwd", "outside allowed directories"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validateRedirectPaths(f, workDir, []string{workDir})
			if err == nil {
				t.Fatal("expected redirect path validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestBashSandboxed_RedirectAllowed(t *testing.T) {
	workDir := t.TempDir()
	os.WriteFile(filepath.Join(workDir, "input.txt"), []byte("hello\n"), 0o644)

	// Input redirect from file in allowed dir
	out, err := BashSandboxed(context.Background(), "cat < "+workDir+"/input.txt", workDir, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", out)
	}

	// Heredoc
	out, err = BashSandboxed(context.Background(), "cat <<EOF\nworld\nEOF", workDir, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "world\n" {
		t.Fatalf("expected 'world\\n', got %q", out)
	}

	// /dev/null output
	out, err = BashSandboxed(context.Background(), "echo hello > /dev/null", workDir, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "" {
		t.Fatalf("expected empty output, got %q", out)
	}
}

func TestBashSandboxed_RedirectPathBlocked(t *testing.T) {
	workDir := t.TempDir()
	_, err := BashSandboxed(context.Background(), "cat < /etc/passwd", workDir, []string{workDir})
	if err == nil {
		t.Fatal("expected error for redirect path outside allowed dirs")
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected outside allowed directories error, got %q", err.Error())
	}
}

func TestExtractPathFromFlag(t *testing.T) {
	tests := []struct {
		flag     string
		expected string
	}{
		// Short flags with embedded paths
		{"-f/etc/passwd", "/etc/passwd"},
		{"-I../include", "../include"},
		{"-L/usr/lib", "/usr/lib"},
		// Long flags with = separator
		{"--file=/etc/passwd", "/etc/passwd"},
		{"--output=/tmp/out", "/tmp/out"},
		// No embedded path
		{"-l", ""},
		{"-la", "a"}, // single-char flag 'l', value 'a'; looksLikePath filters it
		{"--verbose", ""},
		{"--count", ""},
		{"-n", ""},
		// Long flag without =
		{"--file", ""},
	}
	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			got := extractPathFromFlag(tt.flag)
			if got != tt.expected {
				t.Fatalf("extractPathFromFlag(%q) = %q, want %q", tt.flag, got, tt.expected)
			}
		})
	}
}

func TestValidatePaths_Allowed(t *testing.T) {
	workDir := t.TempDir()

	// Create a subdirectory and file for testing
	subDir := filepath.Join(workDir, "subdir")
	os.MkdirAll(subDir, 0o755)
	os.WriteFile(filepath.Join(workDir, "file.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("nested"), 0o644)

	tests := []struct {
		name    string
		command string
	}{
		{"simple filename", "cat file.txt"},
		{"dot path", "ls ."},
		{"dot slash", "cat ./file.txt"},
		{"subdirectory", "cat subdir/nested.txt"},
		{"dot slash subdir", "cat ./subdir/nested.txt"},
		{"find dot", "find . -name '*.txt'"},
		{"no path args", "echo hello"},
		{"flags only", "ls -la"},
		{"workdir absolute", "cat " + workDir + "/file.txt"},
		{"non-path args", "echo hello world"},
		{"grep with pattern", "grep pattern file.txt"},
		{"short flag no value", "ls -la"},
		{"long flag no value", "grep --count pattern"},
		{"long flag with eq local path", "grep --file=" + workDir + "/file.txt pattern"},
		{"short flag with local path", "cat -n ./file.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validatePaths(f, workDir, []string{workDir}); err != nil {
				t.Fatalf("expected path to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidatePaths_Blocked(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"absolute etc", "cat /etc/passwd", "outside allowed directories"},
		{"absolute root", "find /", "outside allowed directories"},
		{"dot dot traversal", "cat ../../../etc/passwd", "outside allowed directories"},
		{"dot dot simple", "cat ../outside", "outside allowed directories"},
		{"absolute tmp", "ls /tmp", "outside allowed directories"},
		{"absolute bin", "strings /bin/ls", "outside allowed directories"},
		{"stat outside", "stat /etc/hostname", "outside allowed directories"},
		{"head outside", "head -5 /etc/hostname", "outside allowed directories"},
		{"du outside", "du -sh /tmp", "outside allowed directories"},
		{"diff outside", "diff /dev/null /dev/null", "outside allowed directories"},
		{"short flag embedded path", "grep -f/etc/passwd pattern", "outside allowed directories"},
		{"long flag embedded path", "grep --file=/etc/passwd pattern", "outside allowed directories"},
		{"short flag dot dot", "grep -f../../etc/passwd pattern", "outside allowed directories"},
		{"cd outside absolute", "cd /tmp", "outside allowed directories"},
		{"cd outside traversal", "cd ../../", "outside allowed directories"},
		{"mkdir outside absolute", "mkdir /tmp/evil", "outside allowed directories"},
		{"mkdir outside traversal", "mkdir ../evil", "outside allowed directories"},
		{"mkdir -p outside", "mkdir -p /tmp/a/b/c", "outside allowed directories"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, []string{workDir})
			if err == nil {
				t.Fatal("expected path validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidatePaths_GitDirectoryBlocked(t *testing.T) {
	workDir := t.TempDir()

	// Create a .git directory structure
	os.MkdirAll(filepath.Join(workDir, ".git", "hooks"), 0o755)
	os.WriteFile(filepath.Join(workDir, ".git", "config"), []byte("[core]"), 0o644)
	os.WriteFile(filepath.Join(workDir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh"), 0o755)

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"cat .git/config", "cat .git/config", "accesses .git directory"},
		{"cat .git/hooks/pre-commit", "cat .git/hooks/pre-commit", "accesses .git directory"},
		{"ls .git", "ls .git", "accesses .git directory"},
		{"ls .git/hooks", "ls .git/hooks", "accesses .git directory"},
		{"find .git", "find .git -name '*.sample'", "accesses .git directory"},
		{"absolute .git", "cat " + workDir + "/.git/config", "accesses .git directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, []string{workDir})
			if err == nil {
				t.Fatal("expected path validation error for .git access")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidatePaths_SymlinkEscape(t *testing.T) {
	workDir := t.TempDir()

	// Create a symlink inside workDir that points outside
	symlink := filepath.Join(workDir, "escape")
	os.Symlink("/etc", symlink)

	f, err := ParseBash("cat escape/passwd")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validatePaths(f, workDir, []string{workDir})
	if err == nil {
		t.Fatal("expected path validation error for symlink escape")
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected outside allowed directories error, got %q", err.Error())
	}
}

func TestValidatePaths_MultipleAllowedPaths(t *testing.T) {
	workDir := t.TempDir()
	extraDir := t.TempDir()

	os.WriteFile(filepath.Join(extraDir, "allowed.txt"), []byte("ok"), 0o644)

	f, err := ParseBash("cat " + extraDir + "/allowed.txt")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	// Should be blocked with only workDir allowed
	err = validatePaths(f, workDir, []string{workDir})
	if err == nil {
		t.Fatal("expected error when extra dir not in allowed paths")
	}

	// Should be allowed with both dirs
	err = validatePaths(f, workDir, []string{workDir, extraDir})
	if err != nil {
		t.Fatalf("expected path to be allowed with multiple allowed paths, got: %v", err)
	}
}

func TestValidatePaths_InSubshellAndPipeline(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
	}{
		{"subshell", "(cat /etc/passwd)"},
		{"pipeline", "cat /etc/passwd | grep root"},
		{"and chain", "true && cat /etc/passwd"},
		{"command substitution", "echo $(cat /etc/passwd)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, []string{workDir})
			if err == nil {
				t.Fatal("expected path validation error")
			}
		})
	}
}

func TestBashSandboxed_PathBlocked(t *testing.T) {
	workDir := t.TempDir()
	_, err := BashSandboxed(context.Background(), "cat /etc/passwd", workDir, []string{workDir})
	if err == nil {
		t.Fatal("expected error for path outside allowed dirs")
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected outside allowed directories error, got %q", err.Error())
	}
}
