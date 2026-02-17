package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox-mcp/config"
	bash_sandboxed "github.com/gartnera/lite-sandbox-mcp/tool/bash_sandboxed"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server over stdio",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

// NewMCPServer creates and configures the MCP server with all tools registered.
func NewMCPServer() *server.MCPServer {
	sandbox := bash_sandboxed.NewSandbox()
	return newMCPServer(sandbox)
}

func newMCPServer(sandbox *bash_sandboxed.Sandbox) *server.MCPServer {
	s := server.NewMCPServer(
		"lite-sandbox-mcp",
		"0.1.0",
	)

	bashTool := mcp.NewTool(
		"bash_sandboxed",
		mcp.WithDescription("Execute a bash command in a lightweight sandbox. The command is parsed and validated before execution."),
		mcp.WithString("command",
			mcp.Description("The bash command to execute"),
			mcp.Required(),
		),
		mcp.WithNumber("timeout",
			mcp.Description("Optional timeout in milliseconds (max 600000ms, default 120000ms)"),
		),
	)

	s.AddTool(bashTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		command, err := request.RequireString("command")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		// Extract optional timeout parameter (default 120000ms = 2 minutes)
		timeoutMs := 120000.0 // default
		if args, ok := request.Params.Arguments.(map[string]any); ok {
			if timeout, ok := args["timeout"]; ok {
				if timeoutFloat, ok := timeout.(float64); ok {
					if timeoutFloat > 600000 {
						return mcp.NewToolResultError("timeout exceeds maximum of 600000ms (10 minutes)"), nil
					}
					if timeoutFloat < 0 {
						return mcp.NewToolResultError("timeout must be positive"), nil
					}
					timeoutMs = timeoutFloat
				}
			}
		}

		cwd, err := os.Getwd()
		if err != nil {
			return mcp.NewToolResultError("failed to get working directory: " + err.Error()), nil
		}

		// Create a context with timeout
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()

		output, err := sandbox.Execute(timeoutCtx, command, cwd, []string{cwd})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(output), nil
	})
	return s
}

func runServe() error {
	slog.Info("starting MCP server")

	sandbox := bash_sandboxed.NewSandbox()

	// Get current working directory for worker pool initialization
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Warn("failed to load config, using defaults", "error", err)
	} else {
		sandbox.UpdateConfig(cfg, cwd)
		slog.Info("loaded config", "extra_commands", cfg.ExtraCommands)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer sandbox.Close() // Clean up worker pool on exit

	go func() {
		err := config.Watch(ctx, func(cfg *config.Config) {
			sandbox.UpdateConfig(cfg, cwd)
			slog.Info("reloaded config", "extra_commands", cfg.ExtraCommands)
		})
		if err != nil && ctx.Err() == nil {
			slog.Error("config watcher failed", "error", err)
		}
	}()

	s := newMCPServer(sandbox)
	return server.ServeStdio(s)
}
