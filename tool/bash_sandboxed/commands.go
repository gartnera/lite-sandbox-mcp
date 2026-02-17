package bash_sandboxed

import "mvdan.cc/sh/v3/syntax"

// allowedCommands is the whitelist of commands that are permitted to execute.
// Only non-destructive, non-code-execution commands are included.
// Excluded categories:
//   - Code execution: python, node, ruby, perl, go, java, gcc, etc. (trivial sandbox bypass)
//   - Networking: curl, wget, ping, nmap, etc. (data exfiltration / remote code fetch)
//   - Archive write: gzip, etc. (arbitrary file writes to sensitive locations)
//   - tar, unzip, ar are allowed with arg validators restricting to read-only operations
//   - Shell escape: eval, exec, source, xargs (bypass command whitelist)
//   - Version control: gh (can execute hooks, fetch remote code)
//   - git is allowed with arg validator restricting to read-only subcommands
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

	// Navigation / directory management
	"cd":    true,
	"mkdir": true,

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

	// Archive inspection (read-only, with arg validators for tar/unzip/ar)
	"tar":     true,
	"unzip":   true,
	"zipinfo": true,
	"ar":      true,

	// Version control (read-only, with arg validator for git)
	"git": true,

	// Scoped write commands (path-validated to stay within allowedPaths)
	"cp":    true,
	"mv":    true,
	"rm":    true,
	"touch": true,
	"chmod": true,
	"ln":    true,
	"sed":   true,

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

// writeCommands is the set of commands that perform write operations.
// Path arguments to these commands are validated against writeAllowedPaths
// rather than readAllowedPaths. This matches the "Scoped write commands"
// category in allowedCommands, plus mkdir.
var writeCommands = map[string]bool{
	"cp":    true,
	"mv":    true,
	"rm":    true,
	"touch": true,
	"chmod": true,
	"ln":    true,
	"sed":   true,
	"mkdir": true,
}

// commandArgValidators is a registry of per-command argument validation functions.
// Commands with dangerous flags (e.g., find -exec, find -delete) register a
// validator here to block those flags while still allowing the command itself.
var commandArgValidators = map[string]func(args []*syntax.Word) error{
	"find":  validateFindArgs,
	"tar":   validateTarArgs,
	"unzip": validateUnzipArgs,
	"ar":    validateArArgs,
	"rm":    validateRmArgs,
	"sed":   validateSedArgs,
}
