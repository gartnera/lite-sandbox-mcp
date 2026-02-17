package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestConfigureMCPServer(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Test with non-existent file
	err := configureMCPServer(tmpDir, "/usr/local/bin/lite-sandbox-mcp")
	if err != nil {
		t.Fatalf("configureMCPServer failed: %v", err)
	}

	// Read and verify the file
	mcpPath := filepath.Join(tmpDir, ".mcp.json")
	data, err := os.ReadFile(mcpPath)
	if err != nil {
		t.Fatalf("failed to read .mcp.json: %v", err)
	}

	var cfg mcpConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse .mcp.json: %v", err)
	}

	if len(cfg.MCPServers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(cfg.MCPServers))
	}

	server, ok := cfg.MCPServers["lite-sandbox-mcp"]
	if !ok {
		t.Fatal("lite-sandbox-mcp server not found")
	}

	if server.Command != "/usr/local/bin/lite-sandbox-mcp" {
		t.Errorf("expected command /usr/local/bin/lite-sandbox-mcp, got %s", server.Command)
	}

	if len(server.Args) != 1 || server.Args[0] != "serve" {
		t.Errorf("expected args [serve], got %v", server.Args)
	}

	// Test updating existing file
	err = configureMCPServer(tmpDir, "/opt/lite-sandbox-mcp")
	if err != nil {
		t.Fatalf("configureMCPServer failed on update: %v", err)
	}

	// Verify the update
	data, err = os.ReadFile(mcpPath)
	if err != nil {
		t.Fatalf("failed to read .mcp.json: %v", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse .mcp.json: %v", err)
	}

	server = cfg.MCPServers["lite-sandbox-mcp"]
	if server.Command != "/opt/lite-sandbox-mcp" {
		t.Errorf("expected updated command /opt/lite-sandbox-mcp, got %s", server.Command)
	}
}

func TestConfigurePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	err := configurePermissions(tmpDir)
	if err != nil {
		t.Fatalf("configurePermissions failed: %v", err)
	}

	// Read and verify the file
	settingsPath := filepath.Join(tmpDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("failed to read settings.json: %v", err)
	}

	var cfg settingsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse settings.json: %v", err)
	}

	if cfg.Permissions == nil {
		t.Fatal("permissions is nil")
	}

	expected := "MCP(lite-sandbox-mcp:bash_sandboxed)"
	if !slices.Contains(cfg.Permissions.Allow, expected) {
		t.Errorf("expected permission %s not found in %v", expected, cfg.Permissions.Allow)
	}

	// Test that running again doesn't duplicate
	err = configurePermissions(tmpDir)
	if err != nil {
		t.Fatalf("configurePermissions failed on second run: %v", err)
	}

	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("failed to read settings.json: %v", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse settings.json: %v", err)
	}

	count := 0
	for _, p := range cfg.Permissions.Allow {
		if p == expected {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected permission to appear once, got %d times", count)
	}
}

func TestConfigureCLAUDEMD(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	err := configureCLAUDEMD(tmpDir)
	if err != nil {
		t.Fatalf("configureCLAUDEMD failed: %v", err)
	}

	// Read and verify the file
	claudeMDPath := filepath.Join(tmpDir, "CLAUDE.md")
	data, err := os.ReadFile(claudeMDPath)
	if err != nil {
		t.Fatalf("failed to read CLAUDE.md: %v", err)
	}

	content := string(data)
	expectedDirective := "ALWAYS prefer using the mcp__lite-sandbox-mcp__bash_sandboxed tool"
	if !contains(content, expectedDirective) {
		t.Errorf("expected CLAUDE.md to contain %q, got:\n%s", expectedDirective, content)
	}

	// Test that running again doesn't duplicate
	err = configureCLAUDEMD(tmpDir)
	if err != nil {
		t.Fatalf("configureCLAUDEMD failed on second run: %v", err)
	}

	data, err = os.ReadFile(claudeMDPath)
	if err != nil {
		t.Fatalf("failed to read CLAUDE.md: %v", err)
	}

	content = string(data)

	// Count occurrences
	count := 0
	for i := 0; i <= len(content)-len(expectedDirective); i++ {
		if content[i:i+len(expectedDirective)] == expectedDirective {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected directive to appear once, got %d times", count)
	}

	// Test appending to existing file
	tmpDir2 := t.TempDir()
	claudeMDPath2 := filepath.Join(tmpDir2, "CLAUDE.md")
	existingContent := "# Existing Content\n\nSome existing instructions.\n"
	if err := os.WriteFile(claudeMDPath2, []byte(existingContent), 0644); err != nil {
		t.Fatalf("failed to write existing CLAUDE.md: %v", err)
	}

	err = configureCLAUDEMD(tmpDir2)
	if err != nil {
		t.Fatalf("configureCLAUDEMD failed with existing file: %v", err)
	}

	data, err = os.ReadFile(claudeMDPath2)
	if err != nil {
		t.Fatalf("failed to read CLAUDE.md: %v", err)
	}

	content = string(data)
	if !contains(content, "# Existing Content") {
		t.Error("existing content was lost")
	}
	if !contains(content, expectedDirective) {
		t.Error("directive was not added")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
