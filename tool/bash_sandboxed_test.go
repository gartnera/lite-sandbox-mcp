package tool

import (
	"context"
	"os"
	"path/filepath"
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
	workDir := t.TempDir()
	out, err := BashSandboxed(context.Background(), "echo hello", workDir, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", out)
	}
}

func TestBashSandboxed_FailingCommand(t *testing.T) {
	workDir := t.TempDir()
	_, err := BashSandboxed(context.Background(), "false", workDir, []string{workDir})
	if err == nil {
		t.Fatal("expected error for failing command")
	}
}

func TestBashSandboxed_InvalidSyntax(t *testing.T) {
	workDir := t.TempDir()
	_, err := BashSandboxed(context.Background(), "echo 'hello", workDir, []string{workDir})
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
		{"jq", "echo '{}' | jq ."},
		{"find", "find . -name '*.go'"},
		{"sort uniq", "echo hello | sort | uniq"},
		{"declare", "declare -a arr"},
		{"export", "export FOO=bar"},
		{"pwd", "pwd"},
		{"date", "date"},
		{"head", "head -5 /etc/hostname"},
		{"tail", "tail -5 /etc/hostname"},
		{"wc", "echo hello | wc -l"},
		{"cut", "echo hello | cut -c1-3"},
		{"tr", "echo hello | tr a-z A-Z"},
		{"diff", "diff /dev/null /dev/null"},
		{"seq", "seq 1 10"},
		{"bc", "echo '1+1' | bc"},
		{"zcat", "zcat --help"},
		{"strings", "strings /bin/ls"},
		{"stat", "stat /etc/hostname"},
		{"file", "file /etc/hostname"},
		{"du", "du -sh /tmp"},
		{"df", "df -h"},
		{"basename", "basename /etc/hostname"},
		{"dirname", "dirname /etc/hostname"},
		{"id", "id"},
		{"uname", "uname -a"},
		{"timeout", "timeout 1 echo hello"},
		{"command", "command -v echo"},
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

		// Code execution (trivial sandbox bypass)
		{"python", "python -c 'import os; os.system(\"rm -rf /\")'", `command "python" is not allowed`},
		{"python3", "python3 -c 'print(1)'", `command "python3" is not allowed`},
		{"node", "node -e 'console.log(1)'", `command "node" is not allowed`},
		{"ruby", "ruby -e 'puts 1'", `command "ruby" is not allowed`},
		{"perl", "perl -e 'print 1'", `command "perl" is not allowed`},
		{"go", "go run main.go", `command "go" is not allowed`},
		{"java", "java Main", `command "java" is not allowed`},
		{"javac", "javac Main.java", `command "javac" is not allowed`},
		{"gcc", "gcc -o a a.c", `command "gcc" is not allowed`},
		{"g++", "g++ -o a a.cpp", `command "g++" is not allowed`},
		{"rustc", "rustc main.rs", `command "rustc" is not allowed`},
		{"make", "make all", `command "make" is not allowed`},

		// Package managers (arbitrary code execution via install scripts)
		{"npm", "npm install", `command "npm" is not allowed`},
		{"npx", "npx something", `command "npx" is not allowed`},
		{"yarn", "yarn install", `command "yarn" is not allowed`},
		{"pip", "pip install requests", `command "pip" is not allowed`},
		{"pip3", "pip3 install requests", `command "pip3" is not allowed`},
		{"cargo", "cargo build", `command "cargo" is not allowed`},

		// Networking (data exfiltration / remote code fetch)
		{"curl", "curl https://example.com", `command "curl" is not allowed`},
		{"wget", "wget https://example.com", `command "wget" is not allowed`},
		{"ping", "ping example.com", `command "ping" is not allowed`},
		{"nmap", "nmap localhost", `command "nmap" is not allowed`},
		{"dig", "dig example.com", `command "dig" is not allowed`},
		{"nslookup", "nslookup example.com", `command "nslookup" is not allowed`},
		{"host", "host example.com", `command "host" is not allowed`},
		{"ip", "ip addr", `command "ip" is not allowed`},
		{"ifconfig", "ifconfig", `command "ifconfig" is not allowed`},
		{"netstat", "netstat -tulpn", `command "netstat" is not allowed`},
		{"ss", "ss -tulpn", `command "ss" is not allowed`},
		{"traceroute", "traceroute example.com", `command "traceroute" is not allowed`},

		// Archive processing (arbitrary file writes)
		{"tar", "tar xf archive.tar", `command "tar" is not allowed`},
		{"unzip", "unzip archive.zip", `command "unzip" is not allowed`},
		{"gzip", "gzip file", `command "gzip" is not allowed`},
		{"gunzip", "gunzip file.gz", `command "gunzip" is not allowed`},

		// Version control (hook execution, remote code fetch)
		{"git", "git clone https://example.com/repo", `command "git" is not allowed`},
		{"gh", "gh pr list", `command "gh" is not allowed`},
		{"svn", "svn checkout https://example.com/repo", `command "svn" is not allowed`},

		// Shell escape commands (bypass whitelist)
		{"eval", "eval echo hello", `command "eval" is not allowed`},
		{"exec", "exec echo hello", `command "exec" is not allowed`},
		{"source", "source /dev/null", `command "source" is not allowed`},
		{"dot source", ". /dev/null", `command "." is not allowed`},
		{"xargs", "echo hello | xargs rm", `command "xargs" is not allowed`},

		// Text processing with write capability
		{"sed", "sed -i 's/a/b/' file", `command "sed" is not allowed`},
		{"awk", "awk '{print}' file", `command "awk" is not allowed`},
		{"tee", "echo hello | tee file", `command "tee" is not allowed`},
		{"csplit", "csplit file /pattern/", `command "csplit" is not allowed`},

		// Interactive / potentially disruptive
		{"top", "top", `command "top" is not allowed`},
		{"htop", "htop", `command "htop" is not allowed`},
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

func TestValidate_BlockedFindFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"find -exec rm", `find . -exec rm {} \;`, `find flag "-exec" is not allowed`},
		{"find -delete", `find . -delete`, `find flag "-delete" is not allowed`},
		{"find -execdir python", `find . -execdir python {} +`, `find flag "-execdir" is not allowed`},
		{"find -ok", `find . -ok rm {} \;`, `find flag "-ok" is not allowed`},
		{"find -okdir", `find . -okdir rm {} \;`, `find flag "-okdir" is not allowed`},
		{"find -fls", `find . -fls /tmp/out`, `find flag "-fls" is not allowed`},
		{"find -fprint", `find . -fprint /tmp/out`, `find flag "-fprint" is not allowed`},
		{"find -fprint0", `find . -fprint0 /tmp/out`, `find flag "-fprint0" is not allowed`},
		{"find -fprintf", `find . -fprintf /tmp/out '%p'`, `find flag "-fprintf" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked find flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_AllowedFindFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"find -name", "find . -name '*.go'"},
		{"find -type f -print", "find . -type f -print"},
		{"find -maxdepth -ls", "find . -maxdepth 2 -ls"},
		{"find -iname", "find . -iname '*.TXT'"},
		{"find -size", "find . -size +1M"},
		{"find -mtime", "find . -mtime -7"},
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
		{"-la", "a"},  // single-char flag 'l', value 'a'; looksLikePath filters it
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
