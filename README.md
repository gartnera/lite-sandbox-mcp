# lite-sandbox-mcp

An MCP (Model Context Protocol) server that exposes a `bash_sandboxed` tool for executing bash commands with strict security validation. Commands are parsed into an AST and validated before execution.

## Security Model

Commands go through three validation layers before execution:

1. **Command whitelist** — Only explicitly allowed, non-destructive commands can run (e.g., `cat`, `ls`, `grep`, `find`). Code execution runtimes, networking tools, package managers, VCS, and file-modifying commands are all blocked.
2. **Structural restrictions** — Redirections (`>`, `>>`, `<`), process substitutions, coprocesses, and dynamic command names are blocked.
3. **Path validation** — All path-like arguments (including paths embedded in flags like `-f/path` and `--file=/path`) are resolved to absolute paths with symlink resolution and checked against an allowed directory list (defaults to cwd).

## Known Limitations

This is a lightweight, best-effort sandbox based on static analysis. It is **not** a security boundary equivalent to containers, VMs, or seccomp. Known bypasses and limitations:

### Path validation bypasses

- **Variable expansions in arguments**: Arguments containing variable expansions (e.g., `cat $HOME/secret`) cannot be statically resolved and are skipped during path validation. The command whitelist limits what damage can be done, but file reads outside allowed directories are possible via variable-constructed paths.
- **Glob expansion**: Glob patterns are validated as literal strings (e.g., `cat ./*.txt` checks the prefix `./`), but bash expands globs at runtime. A glob rooted inside the allowed directory cannot expand outside it, but this relies on the filesystem not containing adversarial symlinks within the allowed directory.
- **`find -exec` and similar**: Commands like `find . -exec cmd {} \;` embed sub-commands in arguments. The path validator sees `-exec` as a flag and `cmd` as a non-path string, but `find` will execute it at runtime. The command whitelist prevents running disallowed binaries via this route only if `find` itself respects the PATH—`find -exec /usr/bin/python` would not be caught by the command whitelist since it's a `find` argument, not a top-level command. However, the path validator **will** block `/usr/bin/python` as an absolute path outside the allowed directory.
- **Multi-char short flag ambiguity**: For short flags like `-la`, the extractor assumes single-char flag + value (extracting `a`). This is conservative and doesn't cause false negatives for path validation since `a` alone won't pass the `looksLikePath` check, but a combined flag like `-abc/etc/passwd` would only check `bc/etc/passwd` (missing the leading character).

### Command validation limitations

- **Allowed commands with dangerous flags**: Some whitelisted commands have flags that could be abused. For example, `find` supports `-delete` and `-exec`, and `xxd` can write files with `-r` when combined with redirections (though redirections are blocked).
- **No syscall-level enforcement**: Validation happens at the AST level before execution. There is no runtime enforcement (no seccomp, no namespace isolation). If a command is allowed and passes validation, it runs with the full privileges of the server process.
- **Bash builtins**: Some allowed builtins like `set`, `export`, and `trap` can modify shell state in ways that affect subsequent commands within the same `bash -c` invocation.

### General limitations

- **Not a security boundary**: This sandbox is defense-in-depth for limiting an LLM's access to the host system. It should not be the sole security mechanism. For untrusted workloads, use OS-level isolation (containers, VMs, seccomp-bpf).
- **Static analysis only**: All validation is based on the parsed AST. Runtime behavior (variable expansion, glob expansion, command output) is not monitored or restricted.

## Usage

```bash
go build -o lite-sandbox-mcp
./lite-sandbox-mcp serve  # Start MCP server over stdio
```

## Development

```bash
go test ./...              # Run all tests
go test -v ./tool/...      # Run tool package tests with verbose output
```
