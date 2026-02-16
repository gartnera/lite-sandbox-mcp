package bash_sandboxed

import (
	"fmt"

	"mvdan.cc/sh/v3/syntax"
)

// validateRedirect checks whether a single redirection is safe.
// Safe redirections:
//   - Heredocs and herestrings (<<, <<-, <<<) — input only
//   - Input fd duplication (<&) — e.g., 0<&3
//   - Output fd duplication (>&) — only when target is a literal fd number (e.g., 2>&1)
//   - Input redirect (<) — allowed (path validation happens separately in validatePaths)
//   - Output redirects (>, >>, >|, &>, &>>) — only to /dev/null
//   - Read-write redirect (<>) — always blocked
func validateRedirect(r *syntax.Redirect) error {
	switch r.Op {
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		// Heredocs/herestrings are input-only, always safe.
		return nil
	case syntax.DplIn:
		// Input fd duplication (e.g., 0<&3) is always safe.
		return nil
	case syntax.DplOut:
		// Output fd duplication (e.g., 2>&1) is safe only when the target
		// is a literal file descriptor number or "-" (to close).
		word := r.Word.Lit()
		if word == "" {
			return fmt.Errorf("redirections with dynamic targets are not allowed")
		}
		// Must be a number (fd) or "-" (close fd).
		for _, c := range word {
			if c >= '0' && c <= '9' {
				continue
			}
			if c == '-' {
				continue
			}
			return fmt.Errorf("output fd duplication (>&) to %q is not allowed: target must be a file descriptor number", word)
		}
		return nil
	case syntax.RdrIn:
		// Input redirect (<) from a file — allowed here; path validation
		// is handled separately by validatePaths via validateRedirectPaths.
		return nil
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		// Output redirects are only allowed to /dev/null.
		word := r.Word.Lit()
		if word == "/dev/null" {
			return nil
		}
		return fmt.Errorf("output redirection to %q is not allowed (only /dev/null is permitted)", word)
	case syntax.RdrInOut:
		return fmt.Errorf("read-write redirection (<>) is not allowed")
	default:
		return fmt.Errorf("redirection operator %v is not allowed", r.Op)
	}
}
