package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// executeInDir runs command in the given dir, using it as the sole
// read+write allowed path.
func executeInDir(t *testing.T, dir, command string) (string, error) {
	t.Helper()
	s := newTestSandbox()
	paths := []string{dir}
	return s.Execute(context.Background(), command, dir, paths, paths)
}

func TestAwk(t *testing.T) {
	tests := []struct {
		name    string
		command string
		setup   func(t *testing.T, dir string)
		wantOut string // substring expected in output; empty means don't check
		wantErr bool
		check   func(t *testing.T, dir string) // extra assertions after execution
	}{
		{
			name:    "basic execution",
			command: `echo -e "a\nb\nc" | awk '{print NR, $0}'`,
			wantOut: "1 a",
		},
		{
			name:    "field separator",
			command: `echo "a:b:c" | awk -F: '{print $2}'`,
			wantOut: "b",
		},
		{
			name:    "variable",
			command: `echo "hello" | awk -v greeting=hi '{print greeting, $0}'`,
			wantOut: "hi hello",
		},
		{
			name: "file arg",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "data.txt"), []byte("foo\nbar\n"), 0600)
			},
			command: `awk '{print toupper($0)}' data.txt`,
			wantOut: "FOO",
		},
		{
			name: "program from -f file",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "prog.awk"), []byte(`{print "line:", $0}`), 0600)
			},
			command: `echo "hello" | awk -f prog.awk`,
			wantOut: "line: hello",
		},
		{
			name:    "env vars via ENVIRON",
			command: `echo x | awk '{print ENVIRON["AWK_TEST_VAR"]}'`,
			setup: func(t *testing.T, dir string) {
				t.Setenv("AWK_TEST_VAR", "hello_from_env")
			},
			wantOut: "hello_from_env",
		},
		{
			name:    "shell output redirect",
			command: `echo "hello" | awk '{print}' > out.txt`,
			check: func(t *testing.T, dir string) {
				data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
				if err != nil {
					t.Fatalf("output file not created: %v", err)
				}
				if strings.TrimSpace(string(data)) != "hello" {
					t.Errorf("unexpected file content: %q", string(data))
				}
			},
		},
		{
			name:    "blocks system()",
			command: `echo x | awk '{system("echo pwned")}'`,
			wantErr: true,
		},
		{
			name:    "blocks command pipe",
			command: `echo x | awk '{print | "cat"}'`,
			wantErr: true,
		},
		{
			name:    "blocks awk file write",
			command: `echo x | awk '{print > "out.txt"}'`,
			wantErr: true,
		},
		{
			name:    "blocks unsupported flag",
			command: `echo x | awk --sandbox-break '{print}'`,
			wantErr: true,
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
					t.Fatal("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOut != "" && !strings.Contains(out, tt.wantOut) {
				t.Errorf("output %q does not contain %q", out, tt.wantOut)
			}
			if tt.check != nil {
				tt.check(t, dir)
			}
		})
	}
}
