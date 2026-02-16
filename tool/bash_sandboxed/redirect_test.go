package bash_sandboxed

import (
	"strings"
	"testing"
)

func TestValidate_AllowedRedirections(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"heredoc", "cat <<EOF\nhello\nEOF"},
		{"heredoc dash", "cat <<-EOF\n\thello\nEOF"},
		{"herestring", "cat <<< 'hello'"},
		{"fd dup stderr to stdout", "echo hello 2>&1"},
		{"fd dup close", "echo hello 2>&-"},
		{"output to /dev/null", "echo hello > /dev/null"},
		{"append to /dev/null", "echo hello >> /dev/null"},
		{"clobber to /dev/null", "echo hello >| /dev/null"},
		{"all to /dev/null", "echo hello &> /dev/null"},
		{"append all to /dev/null", "echo hello &>> /dev/null"},
		{"stderr to /dev/null", "echo hello 2> /dev/null"},
		{"input redirect", "cat < file.txt"},
		{"input fd dup", "cat 0<&3"},
		{"combined stderr and devnull", "echo hello 2>&1 > /dev/null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validate(f); err != nil {
				t.Fatalf("expected redirection to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_BlockedRedirections(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"output redirect to file", "echo hello > file.txt", "output redirection"},
		{"append redirect to file", "echo hello >> file.txt", "output redirection"},
		{"output in pipe to file", "echo hello | grep hello > file.txt", "output redirection"},
		{"clobber to file", "echo hello >| file.txt", "output redirection"},
		{"all to file", "echo hello &> file.txt", "output redirection"},
		{"append all to file", "echo hello &>> file.txt", "output redirection"},
		{"read-write redirect", "echo hello <> file.txt", "read-write redirection"},
		{"fd dup to filename", "echo hello >& file.txt", "output fd duplication"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for redirection")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}
