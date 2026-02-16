package tool

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
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

// validatePaths checks that all path-like arguments in the AST resolve to
// locations under the allowed directories. This prevents reading files outside
// the sandbox boundary (e.g., cat /etc/passwd, cat ../../../etc/shadow).
func validatePaths(f *syntax.File, workDir string, allowedPaths []string) error {
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		callExpr, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for i, arg := range callExpr.Args {
			if i == 0 {
				continue // skip command name
			}
			lit := arg.Lit()
			if lit == "" {
				continue // dynamic/non-literal argument
			}
			var pathToCheck string
			if strings.HasPrefix(lit, "-") {
				// Extract any path embedded in a flag (e.g., -f/etc/passwd, --file=/etc/passwd)
				pathToCheck = extractPathFromFlag(lit)
			} else {
				pathToCheck = lit
			}
			if pathToCheck == "" || !looksLikePath(pathToCheck) {
				continue
			}
			resolved := resolvePath(pathToCheck, workDir)
			if !isUnderAllowedPaths(resolved, allowedPaths) {
				validationErr = fmt.Errorf("path %q resolves to %q which is outside allowed directories", lit, resolved)
				return false
			}
		}
		return true
	})
	return validationErr
}

// looksLikePath returns true if the string looks like it references a filesystem
// path rather than a plain argument. We check arguments that are absolute,
// start with ./ or ../, or contain a path separator.
func looksLikePath(s string) bool {
	if filepath.IsAbs(s) {
		return true
	}
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || s == "." || s == ".." {
		return true
	}
	if strings.Contains(s, "/") {
		return true
	}
	return false
}

// extractPathFromFlag extracts an embedded path value from a flag argument.
// Handles two forms:
//   - Long flags with '=': --file=/etc/passwd → /etc/passwd
//   - Short flags with appended value: -f/etc/passwd → /etc/passwd
//
// Returns empty string if no embedded path is found.
func extractPathFromFlag(flag string) string {
	// Long flag with = separator: --file=/etc/passwd
	if strings.HasPrefix(flag, "--") {
		if idx := strings.Index(flag, "="); idx != -1 {
			return flag[idx+1:]
		}
		return ""
	}
	// Short flag with appended value: -f/etc/passwd
	// Must be -X<value> where X is a single letter
	if len(flag) > 2 && flag[0] == '-' && flag[1] != '-' {
		// The value starts after the flag letter(s). For single-char flags
		// like -f, the value is at index 2. Return it and let looksLikePath decide.
		return flag[2:]
	}
	return ""
}

// resolvePath resolves a potentially relative path to an absolute path,
// handling symlinks for any existing prefix of the path.
func resolvePath(path, workDir string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(workDir, path)
	}
	path = filepath.Clean(path)

	// Try to resolve symlinks on the full path
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved
	}

	// Path doesn't fully exist; resolve the longest existing prefix
	return resolveExistingPrefix(path)
}

// resolveExistingPrefix recursively resolves symlinks on the longest existing
// ancestor of path, then joins the non-existing suffix back.
func resolveExistingPrefix(path string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	if dir == path {
		// Reached root
		return path
	}

	resolved, err := filepath.EvalSymlinks(dir)
	if err == nil {
		return filepath.Join(resolved, base)
	}

	return filepath.Join(resolveExistingPrefix(dir), base)
}

// isUnderAllowedPaths checks whether the resolved path is equal to or nested
// under one of the allowed directories.
func isUnderAllowedPaths(path string, allowedPaths []string) bool {
	for _, allowed := range allowedPaths {
		if path == allowed || strings.HasPrefix(path, allowed+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// BashSandboxed parses, validates, and executes a bash command.
// workDir is the working directory for the command and for resolving relative paths.
// allowedPaths are absolute directories that the command is permitted to access.
// It returns the combined stdout and stderr output.
func BashSandboxed(ctx context.Context, command string, workDir string, allowedPaths []string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	f, err := ParseBash(command)
	if err != nil {
		return "", err
	}

	if err := validate(f); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validatePaths(f, workDir, allowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = workDir
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
