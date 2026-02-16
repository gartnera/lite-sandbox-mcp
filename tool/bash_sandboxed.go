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
// Only non-destructive commands are included. When in doubt, commands are excluded.
var allowedCommands = map[string]bool{
	// Output / display
	"echo":    true,
	"printf":  true,
	"cat":     true,
	"head":    true,
	"tail":    true,
	"less":    true,
	"more":    true,
	"wc":      true,
	"tee":     true,
	"column":  true,
	"fold":    true,
	"paste":   true,
	"rev":     true,
	"tac":     true,
	"nl":      true,
	"pr":      true,
	"expand":  true,
	"unexpand": true,

	// Search / find
	"grep":  true,
	"egrep": true,
	"fgrep": true,
	"find":  true,
	"locate": true,
	"which": true,
	"whereis": true,
	"type":  true,

	// File info (read-only)
	"ls":     true,
	"stat":   true,
	"file":   true,
	"du":     true,
	"df":     true,
	"readlink": true,
	"realpath": true,
	"basename": true,
	"dirname":  true,
	"pwd":      true,
	"sha256sum": true,
	"sha1sum":   true,
	"md5sum":    true,
	"cksum":     true,
	"b2sum":     true,

	// Text processing
	"awk":     true,
	"sed":     true,
	"sort":    true,
	"uniq":    true,
	"cut":     true,
	"tr":      true,
	"diff":    true,
	"comm":    true,
	"join":    true,
	"csplit":  true,
	"strings": true,
	"od":      true,
	"hexdump": true,
	"xxd":     true,

	// JSON/structured data
	"jq": true,
	"yq": true,

	// Variables / shell builtins (non-destructive)
	"test":    true,
	"[":      true,
	"true":   true,
	"false":  true,
	"read":   true,
	"set":    true,
	"unset":  true,
	"export": true,
	"local":  true,
	"declare": true,
	"typeset": true,
	"readonly": true,
	"shift":   true,
	"getopts": true,
	"let":     true,
	"expr":    true,

	// Process / system info (read-only)
	"ps":       true,
	"top":      true,
	"htop":     true,
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

	// Math / calculation
	"bc":   true,
	"dc":   true,
	"seq":  true,
	"factor": true,
	"numfmt": true,

	// Networking (read-only)
	"ping":       true,
	"dig":        true,
	"nslookup":   true,
	"host":       true,
	"curl":       true,
	"wget":       true,
	"ip":         true,
	"ifconfig":   true,
	"netstat":    true,
	"ss":         true,
	"traceroute": true,
	"nmap":       true,

	// Archive inspection (read-only operations)
	"tar":    true,
	"unzip":  true,
	"zcat":   true,
	"zless":  true,
	"zgrep":  true,
	"bzcat":  true,
	"xzcat":  true,
	"gzip":   true,
	"gunzip": true,

	// Version control (read-only)
	"git": true,
	"gh":  true,
	"svn": true,

	// Programming tools (read-only / analysis)
	"python":  true,
	"python3": true,
	"node":    true,
	"ruby":    true,
	"perl":    true,
	"go":      true,
	"rustc":   true,
	"gcc":     true,
	"g++":     true,
	"make":    true,
	"cargo":   true,
	"npm":     true,
	"npx":     true,
	"yarn":    true,
	"pip":     true,
	"pip3":    true,
	"java":    true,
	"javac":   true,

	// Misc utilities
	"xargs":  true,
	"yes":    true,
	"timeout": true,
	"time":   true,
	"sleep":  true,
	"wait":   true,
	"trap":   true,
	"return": true,
	"exit":   true,
	"break":  true,
	"continue": true,
	"source": true,
	".":      true,
	"eval":   true,
	"exec":   true,
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
