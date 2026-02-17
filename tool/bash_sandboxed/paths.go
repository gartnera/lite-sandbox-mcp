package bash_sandboxed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// validatePaths checks that all path-like arguments in the AST resolve to
// locations under the allowed directories. This prevents reading files outside
// the sandbox boundary (e.g., cat /etc/passwd, cat ../../../etc/shadow).
// Write commands (cp, mv, rm, etc.) are checked against writeAllowedPaths;
// all other commands are checked against readAllowedPaths.
func validatePaths(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		callExpr, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		// Determine which allowed paths to use based on command name
		allowedPaths := readAllowedPaths
		if len(callExpr.Args) > 0 {
			cmdName := extractCommandName(callExpr.Args[0])
			if writeCommands[cmdName] {
				allowedPaths = writeAllowedPaths
			}
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
			// Check for .git access even if it doesn't look like a typical path
			if pathToCheck == ".git" || strings.HasPrefix(pathToCheck, ".git/") || strings.HasPrefix(pathToCheck, ".git\\") {
				validationErr = fmt.Errorf("path %q accesses .git directory which is not allowed", lit)
				return false
			}
			if pathToCheck == "" || !looksLikePath(pathToCheck) {
				continue
			}
			resolved := resolvePath(pathToCheck, workDir)
			if !isUnderAllowedPaths(resolved, allowedPaths) {
				validationErr = fmt.Errorf("path %q resolves to %q which is outside allowed directories", lit, resolved)
				return false
			}
			if isGitInternalPath(resolved) {
				validationErr = fmt.Errorf("path %q accesses .git directory which is not allowed", lit)
				return false
			}
		}
		return true
	})
	return validationErr
}

// validateRedirectPaths checks that file targets in redirections resolve to
// locations under the allowed directories. This covers both input redirects (<)
// and output redirects (>, >>, etc.) which must respect path boundaries.
// Input redirects are checked against readAllowedPaths; output redirects are
// checked against writeAllowedPaths. Output redirects to /dev/null are always allowed.
func validateRedirectPaths(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		for _, r := range stmt.Redirs {
			// Only check redirects that reference file paths.
			// fd dups (DplIn, DplOut) and heredocs don't have file targets.
			var allowedPaths []string
			switch r.Op {
			case syntax.RdrIn:
				allowedPaths = readAllowedPaths
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut,
				syntax.RdrAll, syntax.AppAll:
				allowedPaths = writeAllowedPaths
			case syntax.RdrInOut:
				// Read+write; must satisfy write permissions
				allowedPaths = writeAllowedPaths
			default:
				continue
			}
			lit := r.Word.Lit()
			if lit == "" {
				continue
			}
			// /dev/null is always allowed for output
			if lit == "/dev/null" {
				continue
			}
			resolved := resolvePath(lit, workDir)
			if !isUnderAllowedPaths(resolved, allowedPaths) {
				validationErr = fmt.Errorf("redirect path %q resolves to %q which is outside allowed directories", lit, resolved)
				return false
			}
			if isGitInternalPath(resolved) {
				validationErr = fmt.Errorf("redirect path %q accesses .git directory which is not allowed", lit)
				return false
			}
		}
		return true
	})
	return validationErr
}

// isGitInternalPath returns true if the resolved path is inside a .git directory.
// Direct access to .git contents is blocked to prevent reading sensitive data
// (hooks, config) and to force usage through the git command with its validator.
func isGitInternalPath(resolved string) bool {
	// Check each path component for ".git"
	parts := strings.Split(resolved, string(filepath.Separator))
	for _, part := range parts {
		if part == ".git" {
			return true
		}
	}
	return false
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

// validateExpandedPaths checks command arguments after variable expansion.
// This is called by the interpreter's CallHandler, where all variables and
// command substitutions have been resolved to their actual values.
// This catches bypasses like "cat $HOME/secret" that static validation misses.
// Write commands are checked against writeAllowedPaths; others against readAllowedPaths.
func validateExpandedPaths(args []string, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	if len(args) == 0 {
		return nil
	}
	allowedPaths := readAllowedPaths
	if writeCommands[args[0]] {
		allowedPaths = writeAllowedPaths
	}
	for _, arg := range args[1:] {
		if arg == ".git" || strings.HasPrefix(arg, ".git/") || strings.HasPrefix(arg, ".git\\") {
			return fmt.Errorf("path %q accesses .git directory which is not allowed", arg)
		}
		var pathToCheck string
		if strings.HasPrefix(arg, "-") {
			pathToCheck = extractPathFromFlag(arg)
		} else {
			pathToCheck = arg
		}
		if pathToCheck == "" || !looksLikePath(pathToCheck) {
			continue
		}
		resolved := resolvePath(pathToCheck, workDir)
		if !isUnderAllowedPaths(resolved, allowedPaths) {
			return fmt.Errorf("path %q resolves to %q which is outside allowed directories", arg, resolved)
		}
		if isGitInternalPath(resolved) {
			return fmt.Errorf("path %q accesses .git directory which is not allowed", arg)
		}
	}
	return nil
}

// validateOpenPath checks a file path before the interpreter opens it (for
// redirections). This is called by the interpreter's OpenHandler, where
// variables in redirect targets have been expanded to actual paths.
// If the open flags include any write bits, the path is checked against
// writeAllowedPaths; otherwise it is checked against readAllowedPaths.
func validateOpenPath(path string, flag int, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	if path == "/dev/null" {
		return nil
	}
	allowedPaths := readAllowedPaths
	if isWriteFlag(flag) {
		allowedPaths = writeAllowedPaths
	}
	resolved := resolvePath(path, workDir)
	if !isUnderAllowedPaths(resolved, allowedPaths) {
		return fmt.Errorf("path %q resolves to %q which is outside allowed directories", path, resolved)
	}
	if isGitInternalPath(resolved) {
		return fmt.Errorf("path %q accesses .git directory which is not allowed", path)
	}
	return nil
}

// isWriteFlag returns true if the open flags include any write-related bits.
func isWriteFlag(flag int) bool {
	const writeBits = os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_APPEND | os.O_TRUNC
	return flag&writeBits != 0
}
