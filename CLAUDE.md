# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build -o lite-sandbox-mcp    # Build binary
go test ./...                    # Run all tests
go test -v ./tool/...            # Run tool package tests with verbose output
go test -run TestValidate ./tool # Run a specific test
go run . serve                   # Start MCP server over stdio
```

## Architecture

This is an MCP (Model Context Protocol) server that exposes a single `bash_sandboxed` tool for executing bash commands with strict security validation.

**Command flow:** MCP request → `cmd/serve.go:handleBashSandboxed()` → `tool.BashSandboxed()` which does: parse bash AST → validate against whitelist → execute via `bash -c`.

**Security model in `tool/bash_sandboxed.go`:**
- Bash is parsed into an AST using `mvdan.cc/sh/v3`
- `validate()` walks the AST enforcing: commands must be in `allowedCommands` whitelist, no redirections, no process substitutions, no coprocesses, no dynamic command names
- The whitelist is intentionally strict — only read-only, non-destructive commands. Code execution runtimes, networking, archives, shell escapes, VCS, package managers, and file-modifying commands are all blocked.

**Key packages:**
- `cmd/` — Cobra CLI setup and MCP server registration
- `tool/` — Sandbox implementation (parsing, validation, execution)
