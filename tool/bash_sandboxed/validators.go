package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// blockedFindFlags lists find flags that execute commands or modify the filesystem.
var blockedFindFlags = map[string]string{
	"-exec":    "executes arbitrary commands",
	"-execdir": "executes arbitrary commands",
	"-ok":      "executes arbitrary commands",
	"-okdir":   "executes arbitrary commands",
	"-delete":  "deletes files",
	"-fls":     "writes to a file",
	"-fprint":  "writes to a file",
	"-fprint0": "writes to a file",
	"-fprintf": "writes to a file",
}

// validateFindArgs checks that find is not called with dangerous flags.
func validateFindArgs(_ *Sandbox, args []*syntax.Word) error {
	for _, arg := range args {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedFindFlags[lit]; blocked {
			return fmt.Errorf("find flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// blockedTarOps lists tar operation flags that are not read-only.
var blockedTarOps = map[byte]string{
	'x': "extracts files",
	'c': "creates archives",
	'r': "appends to archives",
	'u': "updates archives",
}

// validateTarArgs ensures tar is invoked in list mode only (-t/--list).
// Blocks extract (-x), create (-c), append (-r), update (-u), and --delete.
func validateTarArgs(_ *Sandbox, args []*syntax.Word) error {
	hasListMode := false
	for _, arg := range args[1:] { // skip command name
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		// Check long options
		if lit == "--list" {
			hasListMode = true
			continue
		}
		if lit == "--extract" || lit == "--get" {
			return fmt.Errorf("tar flag %q is not allowed: extracts files", lit)
		}
		if lit == "--create" {
			return fmt.Errorf("tar flag %q is not allowed: creates archives", lit)
		}
		if lit == "--append" {
			return fmt.Errorf("tar flag %q is not allowed: appends to archives", lit)
		}
		if lit == "--update" {
			return fmt.Errorf("tar flag %q is not allowed: updates archives", lit)
		}
		if lit == "--delete" {
			return fmt.Errorf("tar flag %q is not allowed: deletes from archives", lit)
		}
		// Check short options: could be combined like -tzf or standalone like -t
		if len(lit) > 0 && lit[0] == '-' && !strings.HasPrefix(lit, "--") {
			flags := lit[1:]
			for i := 0; i < len(flags); i++ {
				if reason, blocked := blockedTarOps[flags[i]]; blocked {
					return fmt.Errorf("tar flag '-%c' is not allowed: %s", flags[i], reason)
				}
				if flags[i] == 't' {
					hasListMode = true
				}
			}
			continue
		}
		// Handle old-style tar flags without leading dash (e.g., "tf", "tzf")
		// These are common: tar tf archive.tar, tar tzf archive.tar.gz
		if len(lit) > 0 && lit[0] != '-' && arg == args[1] {
			// First non-command argument without dash — could be old-style flags
			for i := 0; i < len(lit); i++ {
				if reason, blocked := blockedTarOps[lit[i]]; blocked {
					return fmt.Errorf("tar flag '%c' is not allowed: %s", lit[i], reason)
				}
				if lit[i] == 't' {
					hasListMode = true
				}
			}
		}
	}
	if !hasListMode {
		return fmt.Errorf("tar is only allowed in list mode (-t/--list)")
	}
	return nil
}

// validateUnzipArgs ensures unzip is invoked in list/test mode only.
// Requires -l (list), -Z (zipinfo mode), or -t (test integrity).
func validateUnzipArgs(_ *Sandbox, args []*syntax.Word) error {
	hasReadOnlyFlag := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if lit == "-l" || lit == "-Z" || lit == "-t" {
			hasReadOnlyFlag = true
		}
		// Check for combined flags like -lv
		if len(lit) > 1 && lit[0] == '-' && !strings.HasPrefix(lit, "--") {
			flags := lit[1:]
			for i := 0; i < len(flags); i++ {
				if flags[i] == 'l' || flags[i] == 'Z' || flags[i] == 't' {
					hasReadOnlyFlag = true
				}
			}
		}
	}
	if !hasReadOnlyFlag {
		return fmt.Errorf("unzip is only allowed with -l (list), -Z (zipinfo), or -t (test) flags")
	}
	return nil
}

// blockedArOps lists ar operation flags that are not read-only.
var blockedArOps = map[byte]string{
	'r': "replaces/inserts members",
	'd': "deletes members",
	'q': "quick appends to archive",
	'x': "extracts members",
	'm': "moves members",
	's': "creates archive index",
}

// validateArArgs ensures ar is invoked in read-only mode only.
// Only permits t (list) and p (print to stdout) operations.
func validateArArgs(_ *Sandbox, args []*syntax.Word) error {
	if len(args) < 2 {
		return fmt.Errorf("ar requires an operation argument")
	}
	// ar operation is typically the first argument (e.g., "ar t archive.a")
	// It can be with or without a leading dash.
	opArg := args[1].Lit()
	if opArg == "" {
		return fmt.Errorf("ar operation must be a literal argument")
	}
	// Strip leading dash if present
	ops := opArg
	if ops[0] == '-' {
		ops = ops[1:]
	}
	hasAllowedOp := false
	for i := 0; i < len(ops); i++ {
		if reason, blocked := blockedArOps[ops[i]]; blocked {
			return fmt.Errorf("ar operation '%c' is not allowed: %s", ops[i], reason)
		}
		if ops[i] == 't' || ops[i] == 'p' {
			hasAllowedOp = true
		}
	}
	if !hasAllowedOp {
		return fmt.Errorf("ar is only allowed with t (list) or p (print) operations")
	}
	return nil
}
