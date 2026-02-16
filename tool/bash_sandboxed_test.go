package tool

import (
	"context"
	"testing"
)

func TestParseBash_Valid(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"simple echo", "echo hello"},
		{"pipe", "echo hello | grep hello"},
		{"variable", "FOO=bar echo $FOO"},
		{"subshell", "(echo hello)"},
		{"multiline", "echo hello\necho world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("expected valid bash, got error: %v", err)
			}
			if f == nil {
				t.Fatal("expected non-nil AST")
			}
		})
	}
}

func TestParseBash_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"unclosed quote", "echo 'hello"},
		{"unclosed paren", "(echo hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBash(tt.command)
			if err == nil {
				t.Fatal("expected error for invalid bash")
			}
		})
	}
}

func TestBashSandboxed_Executes(t *testing.T) {
	out, err := BashSandboxed(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", out)
	}
}

func TestBashSandboxed_FailingCommand(t *testing.T) {
	_, err := BashSandboxed(context.Background(), "false")
	if err == nil {
		t.Fatal("expected error for failing command")
	}
}

func TestBashSandboxed_InvalidSyntax(t *testing.T) {
	_, err := BashSandboxed(context.Background(), "echo 'hello")
	if err == nil {
		t.Fatal("expected error for invalid syntax")
	}
}
