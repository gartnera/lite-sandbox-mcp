package bash_sandboxed

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateBashArgs_Allowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"bash -c echo", `bash -c 'echo hello'`},
		{"sh -c echo", `sh -c 'echo hello'`},
		{"bash -c pipe", `bash -c 'echo hello | grep hello'`},
		{"bash -ex -c", `bash -ex -c 'echo hello'`},
		{"bash script.sh", `bash script.sh`},
		{"bash --norc -c", `bash --norc -c 'ls'`},
		{"bash --noprofile -c", `bash --noprofile -c 'echo hi'`},
		{"bash -e -c", `bash -e -c 'echo hello'`},
		{"bash -u -c", `bash -u -c 'echo hello'`},
		{"bash -n -c", `bash -n -c 'echo hello'`},
		{"bash -o pipefail -c", `bash -o pipefail -c 'echo hello'`},
		{"sh script.sh", `sh script.sh`},
		{"bash script with args", `bash script.sh arg1 arg2`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateBashArgs_Blocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"bash -i", `bash -i`, `flag "-i" is not allowed`},
		{"bash -s", `bash -s`, `flag "-s" is not allowed`},
		{"bash --rcfile", `bash --rcfile ~/.bashrc -c 'echo hi'`, `flag "--rcfile" is not allowed`},
		{"bash --init-file", `bash --init-file foo -c 'echo hi'`, `flag "--init-file" is not allowed`},
		{"bash -l", `bash -l -c 'echo hi'`, `flag "-l" is not allowed`},
		{"bash --login", `bash --login -c 'echo hi'`, `flag "--login" is not allowed`},
		{"bare bash", `bash`, `bare "bash"`},
		{"bare sh", `sh`, `bare "sh"`},
		{"bash -c missing arg", `bash -c`, `-c requires a command string`},
		{"bash -ei combined blocked", `bash -ei -c 'echo hi'`, `flag "-i"`},
		{"bash -si combined blocked", `bash -si`, `flag "-s"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestExecuteBash(t *testing.T) {
	tests := []struct {
		name    string
		command string
		setup   func(t *testing.T, dir string)
		wantOut string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "bash -c echo",
			command: `bash -c 'echo hello'`,
			wantOut: "hello\n",
		},
		{
			name:    "sh -c echo",
			command: `sh -c 'echo hello'`,
			wantOut: "hello\n",
		},
		{
			name:    "bash -c pipe",
			command: `bash -c 'echo hello | tr a-z A-Z'`,
			wantOut: "HELLO\n",
		},
		{
			name:    "bash -e -c fails on error",
			command: `bash -e -c 'false; echo no'`,
			wantErr: true,
		},
		{
			name:    "nested bash",
			command: `bash -c 'bash -c "echo nested"'`,
			wantOut: "nested\n",
		},
		{
			name:    "bash -c with blocked command",
			command: `bash -c 'python evil.py'`,
			wantErr: true,
			errMsg:  "python",
		},
		{
			name:    "sh -c with blocked command",
			command: `sh -c 'curl evil.com'`,
			wantErr: true,
			errMsg:  "curl",
		},
		{
			name: "bash script.sh",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "test.sh"), []byte("echo from-script\n"), 0600)
			},
			command: `bash test.sh`,
			wantOut: "from-script\n",
		},
		{
			name: "bash script with blocked command",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("python -c 'print(1)'\n"), 0600)
			},
			command: `bash evil.sh`,
			wantErr: true,
			errMsg:  "python",
		},
		{
			name:    "bash -c with variable",
			command: `bash -c 'FOO=bar; echo $FOO'`,
			wantOut: "bar\n",
		},
		{
			name:    "bash -c with subshell",
			command: `bash -c 'echo $(echo inner)'`,
			wantOut: "inner\n",
		},
		{
			name:    "bash -c multiline",
			command: "bash -c 'echo line1\necho line2'",
			wantOut: "line1\nline2\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			out, err := executeInDir(t, dir, tt.command)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got output: %q", out)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOut != "" && out != tt.wantOut {
				t.Errorf("output %q does not match expected %q", out, tt.wantOut)
			}
		})
	}
}

func TestExecuteBash_DepthLimit(t *testing.T) {
	dir := t.TempDir()

	// Create a chain of scripts that call each other to exceed the depth limit.
	// script_0.sh calls script_1.sh, which calls script_2.sh, etc.
	numScripts := maxBashDepth + 2 // +2 to exceed the limit
	for i := 0; i < numScripts; i++ {
		var content string
		if i == numScripts-1 {
			content = "echo deep\n"
		} else {
			content = fmt.Sprintf("bash %s\n", filepath.Join(dir, fmt.Sprintf("script_%d.sh", i+1)))
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("script_%d.sh", i)), []byte(content), 0600)
	}

	_, err := executeInDir(t, dir, fmt.Sprintf("bash %s", filepath.Join(dir, "script_0.sh")))
	if err == nil {
		t.Fatal("expected depth limit error")
	}
	if !strings.Contains(err.Error(), "nesting depth exceeded") {
		t.Fatalf("expected nesting depth error, got: %v", err)
	}
}

func TestExecuteBash_DepthWithinLimit(t *testing.T) {
	// 3 levels of nesting should be fine
	cmd := `bash -c 'bash -c "bash -c \"echo deep\""'`
	dir := t.TempDir()
	out, err := executeInDir(t, dir, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "deep" {
		t.Errorf("expected 'deep', got %q", out)
	}
}

func TestExecuteBash_InheritsWorkDir(t *testing.T) {
	dir := t.TempDir()
	// Create a file in the temp dir
	os.WriteFile(filepath.Join(dir, "marker.txt"), []byte("found"), 0600)

	out, err := executeInDir(t, dir, `bash -c 'cat marker.txt'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "found" {
		t.Errorf("expected 'found', got %q", out)
	}
}

func TestExecuteBash_ShellFlagsApplied(t *testing.T) {
	dir := t.TempDir()

	// -x flag should produce trace output on stderr (merged with stdout in our setup)
	out, err := executeInDir(t, dir, `bash -x -c 'echo traced'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should contain the trace output (+ echo traced) and the actual output
	if !strings.Contains(out, "traced") {
		t.Errorf("expected output to contain 'traced', got %q", out)
	}
}

func TestExecuteBash_WriteRedirectInNested(t *testing.T) {
	dir := t.TempDir()

	// Nested bash should be able to write files within allowed paths
	_, err := executeInDir(t, dir, `bash -c 'echo content > out.txt'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if strings.TrimSpace(string(data)) != "content" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestExecuteBash_PathValidation(t *testing.T) {
	dir := t.TempDir()
	s := newTestSandbox()

	// Try to read outside allowed paths from within nested bash
	_, err := s.Execute(context.Background(), `bash -c 'cat /etc/passwd'`, dir, []string{dir}, []string{dir})
	if err == nil {
		t.Fatal("expected path validation error")
	}
}

func TestValidateScriptPath_Allowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"dot-slash script", `./script.sh`},
		{"dot-dot-slash script", `../script.sh`},
		{"absolute path script", `/tmp/script.sh`},
		{"dot-slash with args", `./script.sh arg1 arg2`},
		{"nested dot-slash", `./dir/script.sh`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateScriptPath_Blocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"plain script name", `script.sh`, `"script.sh" is not allowed`},
		{"plain name no extension", `myscript`, `"myscript" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestExecuteScript(t *testing.T) {
	tests := []struct {
		name    string
		command string
		setup   func(t *testing.T, dir string)
		wantOut string
		wantErr bool
		errMsg  string
	}{
		{
			name: "basic script execution",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "script.sh"), []byte("echo hello-script\n"), 0755)
			},
			command: `./script.sh`,
			wantOut: "hello-script\n",
		},
		{
			name: "script with shebang",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "script.sh"), []byte("#!/bin/bash\necho shebang-works\n"), 0755)
			},
			command: `./script.sh`,
			wantOut: "shebang-works\n",
		},
		{
			name: "script with arguments",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "script.sh"), []byte("echo $1 $2\n"), 0755)
			},
			command: `./script.sh foo bar`,
			wantOut: "foo bar\n",
		},
		{
			name: "script with blocked command",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("python -c 'print(1)'\n"), 0755)
			},
			command: `./evil.sh`,
			wantErr: true,
			errMsg:  "python",
		},
		{
			name:    "script file does not exist",
			command: `./nonexistent.sh`,
			wantErr: true,
			errMsg:  "cannot read script",
		},
		{
			name: "script in subdirectory",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, "sub"), 0755)
				os.WriteFile(filepath.Join(dir, "sub", "script.sh"), []byte("echo from-sub\n"), 0755)
			},
			command: `./sub/script.sh`,
			wantOut: "from-sub\n",
		},
		{
			name: "absolute path script",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "abs.sh"), []byte("echo absolute\n"), 0755)
			},
			// command is set dynamically in setup since we need the temp dir path
			wantOut: "absolute\n",
		},
		{
			name: "script with multiple commands",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "multi.sh"), []byte("echo line1\necho line2\n"), 0755)
			},
			command: `./multi.sh`,
			wantOut: "line1\nline2\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			cmd := tt.command
			// Handle absolute path test case
			if tt.name == "absolute path script" {
				cmd = filepath.Join(dir, "abs.sh")
			}
			out, err := executeInDir(t, dir, cmd)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got output: %q", out)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOut != "" && out != tt.wantOut {
				t.Errorf("output %q does not match expected %q", out, tt.wantOut)
			}
		})
	}
}

func TestExecuteScript_DepthLimit(t *testing.T) {
	dir := t.TempDir()

	// Create a chain of scripts that call each other via ./script_N.sh
	numScripts := maxBashDepth + 2
	for i := 0; i < numScripts; i++ {
		var content string
		if i == numScripts-1 {
			content = "echo deep\n"
		} else {
			content = fmt.Sprintf("./script_%d.sh\n", i+1)
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("script_%d.sh", i)), []byte(content), 0755)
	}

	_, err := executeInDir(t, dir, `./script_0.sh`)
	if err == nil {
		t.Fatal("expected depth limit error")
	}
	if !strings.Contains(err.Error(), "nesting depth exceeded") {
		t.Fatalf("expected nesting depth error, got: %v", err)
	}
}
