package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// blockedCargoSubcommands are dangerous subcommands that affect shared state.
var blockedCargoSubcommands = map[string]string{
	"publish": "publishes crates to crates.io registry (affects shared state)",
	"login":   "stores registry credentials",
	"logout":  "removes registry credentials",
	"owner":   "manages crate ownership on the registry",
	"yank":    "removes a version from the registry index",
}

// validateCargoArgs validates cargo commands according to the runtime config.
func validateCargoArgs(args []*syntax.Word, rustCfg *config.RustConfig) error {
	if len(args) < 2 {
		// bare "cargo" with no subcommand is fine (prints help)
		return nil
	}

	// Find the subcommand, skipping global flags
	subcommand := ""
	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			return fmt.Errorf("cargo arguments must be literal strings")
		}
		// Skip global cargo flags that take a value argument
		if lit == "-C" || lit == "--manifest-path" || lit == "--config" || lit == "-Z" {
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
		// Only flags, no subcommand (e.g., "cargo --version")
		return nil
	}

	// Check if publish is explicitly blocked
	if subcommand == "publish" {
		if !rustCfg.RustPublish() {
			return fmt.Errorf("cargo publish is not allowed (runtimes.rust.publish is disabled)")
		}
		return nil
	}

	// Check for other blocked subcommands
	if reason, blocked := blockedCargoSubcommands[subcommand]; blocked {
		return fmt.Errorf("cargo subcommand %q is not allowed: %s", subcommand, reason)
	}

	// Validate specific subcommands
	switch subcommand {
	case "install":
		return validateCargoInstallArgs(args)
	}

	// All other subcommands are allowed (build, check, test, run, fmt, clippy, add, remove, new, init, etc.)
	return nil
}

// validateCargoInstallArgs checks that cargo install is not invoked with remote crate references.
// Local path installs (--path) are allowed, but remote crate installs fetch and execute build scripts.
func validateCargoInstallArgs(args []*syntax.Word) error {
	foundInstall := false
	hasPath := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if !foundInstall {
			if lit == "install" {
				foundInstall = true
			}
			continue
		}
		if lit == "--path" || strings.HasPrefix(lit, "--path=") {
			hasPath = true
		}
	}
	// If --path is specified, it's a local install which is safe
	if hasPath {
		return nil
	}
	// Check if there are positional arguments (crate names) after "install"
	foundInstall = false
	skipNext := false
	for _, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if !foundInstall {
			if lit == "install" {
				foundInstall = true
			}
			continue
		}
		// Skip flags that take values
		if lit == "--version" || lit == "--vers" || lit == "--git" || lit == "--branch" ||
			lit == "--tag" || lit == "--rev" || lit == "--path" || lit == "--root" ||
			lit == "--registry" || lit == "--index" || lit == "--target" ||
			lit == "--target-dir" || lit == "--jobs" || lit == "-j" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(lit, "-") {
			continue
		}
		// Found a positional argument (crate name) - block remote installs
		return fmt.Errorf("cargo install with remote crate references is not allowed: fetches and executes remote build scripts")
	}
	return nil
}
