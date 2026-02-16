package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// blockedRmFlags lists rm flags that bypass safety checks.
var blockedRmFlags = map[string]string{
	"--no-preserve-root": "bypasses root protection",
}

// validateRmArgs checks that rm is not called with dangerous flags.
func validateRmArgs(args []*syntax.Word) error {
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedRmFlags[lit]; blocked {
			return fmt.Errorf("rm flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// validateSedArgs checks that sed expressions don't contain dangerous commands
// and blocks -f/--file since script files contain unvalidated commands.
//
// Dangerous sed commands blocked:
//   - e: executes pattern space as a shell command (GNU extension, complete sandbox bypass)
//   - r/R: reads from arbitrary files (filenames embedded in expression, bypass path validation)
//   - w/W: writes to arbitrary files (filenames embedded in expression, bypass path validation)
//
// Note: GNU sed supports --sandbox which disables e/r/w commands natively,
// but BSD sed does not support this flag, so we parse expressions instead
// to stay portable across both implementations.
func validateSedArgs(args []*syntax.Word) error {
	for _, arg := range args[1:] {
		text := wordText(arg)
		if text == "" {
			continue
		}
		if text == "-f" || text == "--file" || strings.HasPrefix(text, "--file=") {
			return fmt.Errorf("sed flag %q is not allowed: script files bypass command validation", text)
		}
		// Skip flags
		if strings.HasPrefix(text, "-") {
			continue
		}
		if containsSedDangerousCmd(text) {
			return fmt.Errorf("sed commands 'e', 'r', 'R', 'w', 'W' are not allowed: they can execute commands or access files outside path validation")
		}
	}
	return nil
}

// containsSedDangerousCmd checks if a sed expression contains commands that
// execute shell commands or read/write files with embedded filenames.
func containsSedDangerousCmd(expr string) bool {
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != 'e' && c != 'r' && c != 'R' && c != 'w' && c != 'W' {
			continue
		}
		// These commands are valid when:
		// - At the start of the expression (standalone command)
		// - After a sed delimiter (/, ;, newline, |, !)
		// For 'e' as an s/// flag, it appears right after the closing delimiter
		// For w/W/r/R, they're followed by a space/tab and filename
		inCmdPosition := i == 0
		if !inCmdPosition {
			prev := expr[i-1]
			inCmdPosition = prev == '/' || prev == ';' || prev == '\n' || prev == '|' || prev == '!'
		}
		if !inCmdPosition {
			continue
		}
		// 'e' as s///e flag: no following space needed
		if c == 'e' {
			// At end of expression or followed by a delimiter/flag char
			if i+1 >= len(expr) || expr[i+1] == ';' || expr[i+1] == '\n' || expr[i+1] == ' ' || expr[i+1] == '\t' {
				return true
			}
		}
		// r/R/w/W require a space or tab before the filename
		if (c == 'r' || c == 'R' || c == 'w' || c == 'W') && i+1 < len(expr) && (expr[i+1] == ' ' || expr[i+1] == '\t') {
			return true
		}
	}
	return false
}

// wordText extracts the literal text content from a Word node,
// including content inside single and double quotes.
func wordText(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				if lit, ok := dp.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		}
	}
	return sb.String()
}
