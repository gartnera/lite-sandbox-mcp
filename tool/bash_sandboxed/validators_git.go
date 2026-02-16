package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// allowedGitSubcommands is the whitelist of read-only git subcommands.
var allowedGitSubcommands = map[string]bool{
	"status":   true,
	"log":      true,
	"diff":     true,
	"show":     true,
	"blame":    true,
	"branch":   true,
	"tag":      true,
	"shortlog": true,
	"describe": true,
	"rev-parse": true,
	"rev-list":  true,
	"ls-files":  true,
	"ls-tree":   true,
	"cat-file":  true,
	"name-rev":  true,
	"config":    true,
}

// blockedGitBranchFlags lists git branch flags that mutate state.
var blockedGitBranchFlags = map[string]string{
	"-d":       "deletes a branch",
	"-D":       "force deletes a branch",
	"--delete": "deletes a branch",
	"-m":       "renames a branch",
	"-M":       "force renames a branch",
	"--move":   "renames a branch",
	"-c":       "copies a branch",
	"-C":       "force copies a branch",
	"--copy":   "copies a branch",
	"--edit-description": "modifies branch description",
}

// blockedGitTagFlags lists git tag flags that mutate state.
var blockedGitTagFlags = map[string]string{
	"-a":        "creates an annotated tag",
	"--annotate": "creates an annotated tag",
	"-d":        "deletes a tag",
	"--delete":  "deletes a tag",
	"-s":        "creates a signed tag",
	"--sign":    "creates a signed tag",
	"-f":        "force creates/replaces a tag",
	"--force":   "force creates/replaces a tag",
}

// validateGitArgs validates that git is invoked with only read-only subcommands.
// It extracts the subcommand (first non-flag argument after "git"), checks it
// against the allowed whitelist, and applies subcommand-specific flag restrictions.
func validateGitArgs(args []*syntax.Word) error {
	if len(args) < 2 {
		// bare "git" with no subcommand is fine (prints help)
		return nil
	}

	// Find the subcommand, skipping global flags like -C, --git-dir, etc.
	// Flags that take a value argument need to skip the next arg too.
	subcommand := ""
	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			return fmt.Errorf("git arguments must be literal strings")
		}
		// Skip global git flags that take a value argument (skip the flag and its value)
		if lit == "-C" || lit == "-c" || lit == "--git-dir" || lit == "--work-tree" ||
			lit == "--namespace" || lit == "--super-prefix" || lit == "--config-env" {
			skipNext = true
			continue
		}
		// Skip flags (start with -)
		if strings.HasPrefix(lit, "-") {
			continue
		}
		subcommand = lit
		break
	}

	if subcommand == "" {
		// Only flags, no subcommand (e.g., "git --version")
		return nil
	}

	if !allowedGitSubcommands[subcommand] {
		return fmt.Errorf("git subcommand %q is not allowed", subcommand)
	}

	// Apply subcommand-specific flag restrictions
	switch subcommand {
	case "branch":
		return validateGitBranchArgs(args)
	case "tag":
		return validateGitTagArgs(args)
	case "config":
		return validateGitConfigArgs(args)
	}

	return nil
}

// validateGitBranchArgs checks that git branch is not invoked with mutation flags.
func validateGitBranchArgs(args []*syntax.Word) error {
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedGitBranchFlags[lit]; blocked {
			return fmt.Errorf("git branch flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// validateGitTagArgs checks that git tag is not invoked with mutation flags.
func validateGitTagArgs(args []*syntax.Word) error {
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if reason, blocked := blockedGitTagFlags[lit]; blocked {
			return fmt.Errorf("git tag flag %q is not allowed: %s", lit, reason)
		}
	}
	return nil
}

// validateGitConfigArgs checks that git config is only used with --list or --get.
// Without these flags, git config could set values like core.pager or core.editor
// to arbitrary commands.
func validateGitConfigArgs(args []*syntax.Word) error {
	hasReadOnlyFlag := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if lit == "--list" || lit == "-l" || lit == "--get" || lit == "--get-all" ||
			lit == "--get-regexp" || lit == "--get-urlmatch" {
			hasReadOnlyFlag = true
		}
	}
	if !hasReadOnlyFlag {
		return fmt.Errorf("git config is only allowed with --list, --get, --get-all, --get-regexp, or --get-urlmatch")
	}
	return nil
}
