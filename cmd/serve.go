package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox-mcp/tool"
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
	)

	s.AddTool(bashTool, handleBashSandboxed)
	return s
}

func runServe() error {
	slog.Info("starting MCP server")
	s := NewMCPServer()
	return server.ServeStdio(s)
}

func handleBashSandboxed(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := request.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError("missing required parameter: command"), nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return mcp.NewToolResultError("failed to get working directory: " + err.Error()), nil
	}

	output, err := tool.BashSandboxed(ctx, command, cwd, []string{cwd})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(output), nil
}
