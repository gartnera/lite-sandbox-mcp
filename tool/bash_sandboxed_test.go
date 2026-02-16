package tool

import (
	"context"
	"strings"
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

func TestValidate_AllowedCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"echo", "echo hello"},
		{"ls", "ls -la"},
		{"grep pipe", "echo foo | grep foo"},
		{"cat", "cat /etc/hostname"},
		{"variable assignment", "FOO=bar"},
		{"variable with command", "FOO=bar echo $FOO"},
		{"if statement", "if true; then echo yes; fi"},
		{"for loop", "for i in 1 2 3; do echo $i; done"},
		{"while loop", "while true; do echo loop; break; done"},
		{"case statement", "case $x in foo) echo foo;; esac"},
		{"subshell", "(echo hello)"},
		{"block", "{ echo hello; }"},
		{"and operator", "true && echo yes"},
		{"or operator", "false || echo no"},
		{"test bracket", "[ -f /etc/passwd ]"},
		{"bash test", "[[ -f /etc/passwd ]]"},
		{"command substitution", "echo $(whoami)"},
		{"backtick substitution", "echo `whoami`"},
		{"arithmetic", "echo $((1 + 2))"},
		{"function declaration", "foo() { echo hello; }"},
		{"negation", "! false"},
		{"background", "sleep 1 &"},
		{"multiline", "echo hello\necho world"},
		{"git", "git status"},
		{"python", "python3 -c 'print(1)'"},
		{"jq", "echo '{}' | jq ."},
		{"sed", "echo hello | sed 's/h/H/'"},
		{"awk", "echo hello | awk '{print $1}'"},
		{"find", "find . -name '*.go'"},
		{"sort uniq", "echo hello | sort | uniq"},
		{"curl", "curl -s https://example.com"},
		{"xargs", "echo hello | xargs echo"},
		{"declare", "declare -a arr"},
		{"export", "export FOO=bar"},
		{"source", "source /dev/null"},
		{"dot source", ". /dev/null"},
		{"pwd", "pwd"},
		{"date", "date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_BlockedCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"rm", "rm file.txt", `command "rm" is not allowed`},
		{"rm -rf", "rm -rf /", `command "rm" is not allowed`},
		{"mv", "mv a b", `command "mv" is not allowed`},
		{"cp", "cp a b", `command "cp" is not allowed`},
		{"chmod", "chmod 777 file", `command "chmod" is not allowed`},
		{"chown", "chown root file", `command "chown" is not allowed`},
		{"mkdir", "mkdir dir", `command "mkdir" is not allowed`},
		{"rmdir", "rmdir dir", `command "rmdir" is not allowed`},
		{"touch", "touch file", `command "touch" is not allowed`},
		{"dd", "dd if=/dev/zero of=file", `command "dd" is not allowed`},
		{"mkfs", "mkfs /dev/sda", `command "mkfs" is not allowed`},
		{"mount", "mount /dev/sda /mnt", `command "mount" is not allowed`},
		{"umount", "umount /mnt", `command "umount" is not allowed`},
		{"kill", "kill 1234", `command "kill" is not allowed`},
		{"killall", "killall nginx", `command "killall" is not allowed`},
		{"reboot", "reboot", `command "reboot" is not allowed`},
		{"shutdown", "shutdown now", `command "shutdown" is not allowed`},
		{"systemctl", "systemctl stop nginx", `command "systemctl" is not allowed`},
		{"useradd", "useradd user", `command "useradd" is not allowed`},
		{"userdel", "userdel user", `command "userdel" is not allowed`},
		{"passwd", "passwd", `command "passwd" is not allowed`},
		{"su", "su root", `command "su" is not allowed`},
		{"sudo", "sudo echo hi", `command "sudo" is not allowed`},
		{"iptables", "iptables -F", `command "iptables" is not allowed`},
		{"crontab", "crontab -l", `command "crontab" is not allowed`},
		{"ln", "ln -s a b", `command "ln" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedRedirections(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"output redirect", "echo hello > file.txt"},
		{"append redirect", "echo hello >> file.txt"},
		{"input redirect", "cat < file.txt"},
		{"heredoc", "cat <<EOF\nhello\nEOF"},
		{"fd redirect", "echo hello 2>&1"},
		{"output in pipe", "echo hello | grep hello > file.txt"},
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
			if !strings.Contains(err.Error(), "redirect") {
				t.Fatalf("expected redirect error, got %q", err.Error())
			}
		})
	}
}

func TestValidate_BlockedProcSubst(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"process substitution input", "diff <(echo a) <(echo b)"},
		{"process substitution output", "echo hello > >(cat)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for process substitution")
			}
		})
	}
}

func TestValidate_BlockedInPipeline(t *testing.T) {
	f, err := ParseBash("echo hello | rm file.txt")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in pipeline")
	}
	if !strings.Contains(err.Error(), `"rm"`) {
		t.Fatalf("expected rm error, got %q", err.Error())
	}
}

func TestValidate_BlockedInSubshell(t *testing.T) {
	f, err := ParseBash("(rm file.txt)")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in subshell")
	}
}

func TestValidate_BlockedInIfBody(t *testing.T) {
	f, err := ParseBash("if true; then rm file.txt; fi")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in if body")
	}
}

func TestValidate_BlockedInForLoop(t *testing.T) {
	f, err := ParseBash("for i in 1 2 3; do rm $i; done")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in for loop")
	}
}

func TestValidate_BlockedInCommandSubstitution(t *testing.T) {
	f, err := ParseBash("echo $(rm file.txt)")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in command substitution")
	}
}

func TestValidate_DynamicCommandBlocked(t *testing.T) {
	// Commands that can't be statically determined should be blocked
	f, err := ParseBash("$CMD arg1 arg2")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validate(f)
	if err == nil {
		t.Fatal("expected validation error for dynamic command name")
	}
}
