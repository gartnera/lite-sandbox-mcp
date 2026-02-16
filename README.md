# lite-sandbox-mcp

An MCP (Model Context Protocol) server that provides a `bash_sandboxed` tool a replacment for basoc shell access in AI coding agents. The goal is to let agents run shell commands freely without per-command permission prompts, while enforcing safety through static analysis — commands are parsed into an AST and validated against a whitelist before execution.

## Configuring with Claude Code

### 1. Add the MCP server

Add this to `.mcp.json` in your project root (or `~/.claude/.mcp.json` for global):

```json
{
  "mcpServers": {
    "lite-sandbox-mcp": {
      "command": "/path/to/lite-sandbox-mcp",
      "args": ["serve"]
    }
  }
}
```

Replace `/path/to/lite-sandbox-mcp` with the actual path to the built binary.

### 2. Auto-allow the tool

Add this to `~/.claude/settings.json` so Claude Code never prompts for permission:

```json
{
  "permissions": {
    "allow": [
      "MCP(lite-sandbox-mcp:bash_sandboxed)"
    ]
  }
}
```

### 3. Direct Claude to prefer the sandboxed tool

Add the following to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md`:

```markdown
ALWAYS prefer using the mcp__lite-sandbox-mcp__bash_sandboxed tool for running shell commands instead of the built-in Bash tool. The sandboxed tool is pre-approved and requires no permission prompts.
```

> **Note**: The tool name follows the pattern `mcp__<server-name>__<tool-name>`. If you named the server differently in your MCP config (e.g. `lite-sandbox`), adjust the tool name accordingly (e.g. `mcp__lite-sandbox__bash_sandboxed`).

## Configuration

Extra commands can be allowed via a config file at the platform-appropriate location:

- **Linux**: `~/.config/lite-sandbox-mcp/config.yaml`
- **macOS**: `~/Library/Application Support/lite-sandbox-mcp/config.yaml`

```yaml
extra_commands:
  - curl
  - python3
```

The config file is automatically reloaded when changed — no server restart needed.

### CLI config management

```bash
# Print config file path
lite-sandbox-mcp config path

# Show current configuration
lite-sandbox-mcp config show

# Add extra allowed commands
lite-sandbox-mcp config extra-commands add curl wget

# List extra allowed commands
lite-sandbox-mcp config extra-commands list

# Remove extra allowed commands
lite-sandbox-mcp config extra-commands remove curl
```

## Security Model

Commands go through three validation layers before execution:

1. **Command whitelist** — Only explicitly allowed, non-destructive commands can run (e.g., `cat`, `ls`, `grep`, `find`). Code execution runtimes, networking tools, package managers, and shell escape commands are all blocked. Additional commands can be allowed via config.
2. **Argument validation** — Per-command validators block dangerous flags (e.g., `find -exec`, `tar -x`, `git push`). Write commands (`cp`, `mv`, `rm`, `sed`, etc.) are allowed but path-validated.
3. **Structural restrictions** — Process substitutions, coprocesses, read-write redirections, and dynamic command names are blocked. Output redirections are allowed but path-validated.
4. **Path validation** — All path-like arguments (including paths embedded in flags like `-f/path` and `--file=/path`) are resolved to absolute paths with symlink resolution and checked against an allowed directory list (defaults to cwd). Access to `.git` directories is blocked.

## Known Limitations

This is a lightweight, best-effort sandbox based on static analysis. It is **not** a security boundary equivalent to containers, VMs, or seccomp. Known bypasses and limitations:

### Path validation bypasses

- **Variable expansions in arguments**: Arguments containing variable expansions (e.g., `cat $HOME/secret`) cannot be statically resolved and are skipped during path validation. The command whitelist limits what damage can be done, but file reads outside allowed directories are possible via variable-constructed paths.
- **Glob expansion**: Glob patterns are validated as literal strings (e.g., `cat ./*.txt` checks the prefix `./`), but bash expands globs at runtime. A glob rooted inside the allowed directory cannot expand outside it, but this relies on the filesystem not containing adversarial symlinks within the allowed directory.
- **Multi-char short flag ambiguity**: For short flags like `-la`, the extractor assumes single-char flag + value (extracting `a`). This is conservative and doesn't cause false negatives for path validation since `a` alone won't pass the `looksLikePath` check, but a combined flag like `-abc/etc/passwd` would only check `bc/etc/passwd` (missing the leading character).

### Command validation limitations

- **Per-command argument validation**: Some whitelisted commands have dangerous flags that are blocked via argument validators. For `find`, the flags `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fls`, `-fprint`, `-fprint0`, and `-fprintf` are all blocked. Other commands like `xxd` can write files with `-r` when combined with redirections (though redirections are blocked).
- **No syscall-level enforcement**: Validation happens at the AST level before execution. There is no runtime enforcement (no seccomp, no namespace isolation). If a command is allowed and passes validation, it runs with the full privileges of the server process.
- **Bash builtins**: Some allowed builtins like `set`, `export`, and `trap` can modify shell state in ways that affect subsequent commands within the same `bash -c` invocation.

### General limitations

- **Not a security boundary**: This sandbox is defense-in-depth for limiting an LLM's access to the host system. It should not be the sole security mechanism. For untrusted workloads, use OS-level isolation (containers, VMs, seccomp-bpf).
- **Static analysis only**: All validation is based on the parsed AST. Runtime behavior (variable expansion, glob expansion, command output) is not monitored or restricted.
- **Extra commands bypass validation**: Commands added via `extra_commands` config are allowed without any argument validation. Only add commands you trust.

## Building

```bash
go build -o lite-sandbox-mcp
```

## Development

```bash
go test ./...              # Run all tests
go test -v ./tool/...      # Run tool package tests with verbose output
```
