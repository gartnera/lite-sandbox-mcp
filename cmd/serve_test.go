package cmd

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func setupClient(t *testing.T) *client.Client {
	t.Helper()
	ctx := context.Background()

	s := NewMCPServer()
	c, err := client.NewInProcessClient(s)
	if err != nil {
		t.Fatalf("failed to create in-process client: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo: mcp.Implementation{
				Name:    "test-client",
				Version: "0.0.1",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}

	return c
}

func TestBashSandboxedTool_Success(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash_sandboxed",
			Arguments: map[string]any{"command": "echo hello"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %+v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("expected content in result")
	}
	text, ok := result.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if text.Text != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", text.Text)
	}
}

func TestBashSandboxedTool_InvalidSyntax(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash_sandboxed",
			Arguments: map[string]any{"command": "echo 'hello"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for invalid syntax")
	}
}

func TestBashSandboxedTool_MissingCommand(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash_sandboxed",
			Arguments: map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for missing command")
	}
}

func TestListTools(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	if len(tools.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools.Tools))
	}
	if tools.Tools[0].Name != "bash_sandboxed" {
		t.Fatalf("expected tool name 'bash_sandboxed', got %q", tools.Tools[0].Name)
	}
}
