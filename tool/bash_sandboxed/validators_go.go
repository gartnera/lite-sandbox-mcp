package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox-mcp/config"
	"mvdan.cc/sh/v3/syntax"
)

// blockedGoSubcommands are dangerous subcommands that allow arbitrary execution.
var blockedGoSubcommands = map[string]string{
	"generate": "runs arbitrary shell commands from //go:generate directives",
}

// validateGoArgs validates go commands according to the runtime config.
func validateGoArgs(args []*syntax.Word, goCfg *config.GoConfig) error {
	if len(args) < 2 {
		// bare "go" with no subcommand is fine (prints help)
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
			return fmt.Errorf("go arguments must be literal strings")
		}
		// Skip global go flags that take a value argument
		if lit == "-C" {
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
		// Only flags, no subcommand (e.g., "go --help")
		return nil
	}

	// Check if generate is explicitly blocked
	if subcommand == "generate" {
		if !goCfg.GoGenerate() {
			return fmt.Errorf("go generate is not allowed (runtimes.go.generate is disabled)")
		}
		return nil
	}

	// Check for other blocked subcommands
	if reason, blocked := blockedGoSubcommands[subcommand]; blocked {
		return fmt.Errorf("go subcommand %q is not allowed: %s", subcommand, reason)
	}

	// Validate specific subcommands
	switch subcommand {
	case "run":
		return validateGoRunArgs(args)
	case "install":
		return validateGoInstallArgs(args)
	}

	// All other subcommands are allowed (build, test, mod, list, etc.)
	return nil
}

// validateGoRunArgs checks that go run is not invoked with remote package references or -exec flag.
func validateGoRunArgs(args []*syntax.Word) error {
	foundRun := false
	skipNext := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if !foundRun {
			if lit == "run" {
				foundRun = true
			}
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		// Check for -exec flag
		if lit == "-exec" {
			return fmt.Errorf("go run -exec is not allowed: arbitrary command execution via external program")
		}
		// Flags that take values
		if strings.HasPrefix(lit, "-") && !strings.Contains(lit, "=") {
			// Could be a flag that takes a value, skip next
			skipNext = true
			continue
		}
		// Check if argument contains @ (remote package reference)
		if strings.Contains(lit, "@") {
			return fmt.Errorf("go run with remote package references (@) is not allowed: fetches and executes remote code")
		}
	}
	return nil
}

// validateGoInstallArgs checks that go install is not invoked with remote package references.
func validateGoInstallArgs(args []*syntax.Word) error {
	foundInstall := false
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
		// Skip flags
		if strings.HasPrefix(lit, "-") {
			continue
		}
		// Check if argument contains @ (remote package reference)
		if strings.Contains(lit, "@") {
			return fmt.Errorf("go install with remote package references (@) is not allowed: fetches and installs remote code")
		}
	}
	return nil
}
