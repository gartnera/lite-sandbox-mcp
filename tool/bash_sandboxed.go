package tool

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ParseBash parses a command string as bash and returns the AST.
func ParseBash(command string) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse bash: %w", err)
	}
	return f, nil
}

// allowedCommands is the whitelist of commands that are permitted to execute.
// Only non-destructive, non-code-execution commands are included.
// Excluded categories:
//   - Code execution: python, node, ruby, perl, go, java, gcc, etc. (trivial sandbox bypass)
//   - Networking: curl, wget, ping, nmap, etc. (data exfiltration / remote code fetch)
//   - Archive write: tar, unzip, gzip, etc. (arbitrary file writes to sensitive locations)
//   - Shell escape: eval, exec, source, xargs (bypass command whitelist)
//   - Version control: git, gh (can execute hooks, fetch remote code)
//   - Package managers: npm, pip, cargo, etc. (arbitrary code execution via install scripts)
//
// When in doubt, commands are excluded.
var allowedCommands = map[string]bool{
	// Output / display (pure readers, no write capability)
	"echo":     true,
	"printf":   true,
	"cat":      true,
	"head":     true,
	"tail":     true,
	"less":     true,
	"more":     true,
	"wc":       true,
	"column":   true,
	"fold":     true,
	"paste":    true,
	"rev":      true,
	"tac":      true,
	"nl":       true,
	"pr":       true,
	"expand":   true,
	"unexpand": true,

	// Search / find (read-only)
	"grep":    true,
	"egrep":   true,
	"fgrep":   true,
	"find":    true,
	"locate":  true,
	"which":   true,
	"whereis": true,
	"type":    true,

	// File info (read-only, no modification capability)
	"ls":        true,
	"stat":      true,
	"file":      true,
	"du":        true,
	"df":        true,
	"readlink":  true,
	"realpath":  true,
	"basename":  true,
	"dirname":   true,
	"pwd":       true,
	"sha256sum": true,
	"sha1sum":   true,
	"md5sum":    true,
	"cksum":     true,
	"b2sum":     true,

	// Text processing (stdin/stdout only, no file write capability)
	"sort":    true,
	"uniq":    true,
	"cut":     true,
	"tr":      true,
	"diff":    true,
	"comm":    true,
	"join":    true,
	"strings": true,
	"od":      true,
	"hexdump": true,
	"xxd":     true,

	// JSON/structured data (stdin/stdout processors)
	"jq": true,
	"yq": true,

	// Shell builtins (non-destructive, no escape capability)
	"test":     true,
	"[":        true,
	"true":     true,
	"false":    true,
	"read":     true,
	"set":      true,
	"unset":    true,
	"export":   true,
	"local":    true,
	"declare":  true,
	"typeset":  true,
	"readonly": true,
	"shift":    true,
	"getopts":  true,
	"let":      true,
	"expr":     true,

	// Process / system info (read-only)
	"ps":       true,
	"uptime":   true,
	"uname":    true,
	"hostname": true,
	"whoami":   true,
	"id":       true,
	"groups":   true,
	"env":      true,
	"printenv": true,
	"date":     true,
	"cal":      true,

	// Math / calculation (pure computation)
	"bc":     true,
	"dc":     true,
	"seq":    true,
	"factor": true,
	"numfmt": true,

	// Compressed file readers (read-only, no extraction)
	"zcat":  true,
	"zless": true,
	"zgrep": true,
	"bzcat": true,
	"xzcat": true,

	// Control flow / job control
	"sleep":    true,
	"wait":     true,
	"trap":     true,
	"return":   true,
	"exit":     true,
	"break":    true,
	"continue": true,
	"timeout":  true,
	"time":     true,
	"yes":      true,

	// Safe introspection
	"command": true,
	"builtin": true,
	"hash":    true,
	"help":    true,
	"man":     true,
	"info":    true,
	"apropos": true,
}

// validate walks the parsed AST and enforces:
// 1. All commands must be in the allowedCommands whitelist
// 2. No redirections (>, >>, <, etc.) are permitted
// 3. No process substitutions are permitted
func validate(f *syntax.File) error {
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			if len(n.Redirs) > 0 {
				validationErr = fmt.Errorf("redirections are not allowed")
				return false
			}
		case *syntax.CallExpr:
			if len(n.Args) > 0 {
				cmdName := extractCommandName(n.Args[0])
				if cmdName == "" {
					validationErr = fmt.Errorf("dynamic command names are not allowed")
					return false
				}
				if !allowedCommands[cmdName] {
					validationErr = fmt.Errorf("command %q is not allowed", cmdName)
					return false
				}
			}
		case *syntax.ProcSubst:
			validationErr = fmt.Errorf("process substitutions are not allowed")
			return false
		case *syntax.CoprocClause:
			validationErr = fmt.Errorf("coprocesses are not allowed")
			return false
		}
		return true
	})
	return validationErr
}

// extractCommandName returns the literal name of a command from a Word node.
// Returns empty string if the command name cannot be statically determined.
func extractCommandName(w *syntax.Word) string {
	return w.Lit()
}

// BashSandboxed parses, validates, and executes a bash command.
// It returns the combined stdout and stderr output.
func BashSandboxed(ctx context.Context, command string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	f, err := ParseBash(command)
	if err != nil {
		return "", err
	}

	if err := validate(f); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	output := out.String()
	if err != nil {
		return output, fmt.Errorf("command failed: %w\noutput: %s", err, output)
	}
	return output, nil
}
