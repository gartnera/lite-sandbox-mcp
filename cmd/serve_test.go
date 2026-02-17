package cmd

import (
	"context"
	"strings"
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
			Name:      "bash",
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
			Name:      "bash",
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
			Name:      "bash",
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
	if tools.Tools[0].Name != "bash" {
		t.Fatalf("expected tool name 'bash', got %q", tools.Tools[0].Name)
	}
}

func TestBashSandboxedTool_Timeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with a command that takes longer than the timeout
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "sleep 10",
				"timeout": 100.0, // 100ms timeout
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for timeout")
	}
	// Check that the error message mentions context deadline
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if !strings.Contains(text.Text, "context deadline exceeded") {
				t.Fatalf("expected timeout error message, got: %q", text.Text)
			}
		}
	}
}

func TestBashSandboxedTool_CompletesBeforeTimeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with a command that completes before the timeout
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "echo quick",
				"timeout": 5000.0, // 5 second timeout, plenty of time
			},
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
	if text.Text != "quick\n" {
		t.Fatalf("expected 'quick\\n', got %q", text.Text)
	}
}

func TestBashSandboxedTool_DefaultTimeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test without specifying timeout (should use default of 120000ms)
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "bash",
			Arguments: map[string]any{"command": "echo default"},
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
	if text.Text != "default\n" {
		t.Fatalf("expected 'default\\n', got %q", text.Text)
	}
}

func TestBashSandboxedTool_TimeoutExceedsMaximum(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with timeout exceeding maximum (600000ms)
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "echo test",
				"timeout": 700000.0, // Exceeds max
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for timeout exceeding maximum")
	}
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if !strings.Contains(text.Text, "exceeds maximum") {
				t.Fatalf("expected max timeout error message, got: %q", text.Text)
			}
		}
	}
}

func TestBashSandboxedTool_NegativeTimeout(t *testing.T) {
	c := setupClient(t)
	ctx := context.Background()

	// Test with negative timeout
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "bash",
			Arguments: map[string]any{
				"command": "echo test",
				"timeout": -1000.0,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for negative timeout")
	}
	if len(result.Content) > 0 {
		if text, ok := result.Content[0].(mcp.TextContent); ok {
			if !strings.Contains(text.Text, "must be positive") {
				t.Fatalf("expected positive timeout error message, got: %q", text.Text)
			}
		}
	}
}
