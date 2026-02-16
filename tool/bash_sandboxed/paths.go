package bash_sandboxed

import (
	"fmt"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

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

// validateRedirectPaths checks that file targets in redirections resolve to
// locations under the allowed directories. This covers input redirects (<)
// which are permitted by validateRedirect but must still respect path boundaries.
func validateRedirectPaths(f *syntax.File, workDir string, allowedPaths []string) error {
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
			switch r.Op {
			case syntax.RdrIn, syntax.RdrInOut:
				// These take a file path as target.
			default:
				continue
			}
			lit := r.Word.Lit()
			if lit == "" || !looksLikePath(lit) {
				continue
			}
			resolved := resolvePath(lit, workDir)
			if !isUnderAllowedPaths(resolved, allowedPaths) {
				validationErr = fmt.Errorf("redirect path %q resolves to %q which is outside allowed directories", lit, resolved)
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
