package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPreflightHookValidCommand(t *testing.T) {
	// A sandbox-valid command should produce a deny JSON response
	input := preflightHookInput{
		ToolName: "Bash",
		CWD:      t.TempDir(),
	}
	input.ToolInput.Command = "echo hello"

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output == "" {
		t.Fatal("expected deny response for sandbox-valid command, got empty output")
	}

	var resp preflightHookOutput
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatalf("failed to parse response JSON: %v", err)
	}

	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("expected deny, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
	if resp.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("expected PreToolUse, got %s", resp.HookSpecificOutput.HookEventName)
	}
}

func TestPreflightHookInvalidCommand(t *testing.T) {
	// A command that would fail sandbox validation should produce no output (allow)
	input := preflightHookInput{
		ToolName: "Bash",
		CWD:      t.TempDir(),
	}
	input.ToolInput.Command = "python script.py"

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output != "" {
		t.Errorf("expected empty output for invalid command, got: %s", output)
	}
}

func TestPreflightHookMalformedJSON(t *testing.T) {
	// Malformed JSON should produce no output (fail open)
	output := capturePreflightHook(t, []byte("{invalid json"))
	if output != "" {
		t.Errorf("expected empty output for malformed JSON, got: %s", output)
	}
}

func TestPreflightHookNonBashTool(t *testing.T) {
	// Non-Bash tool_name should produce no output (allow)
	input := preflightHookInput{
		ToolName: "Read",
		CWD:      t.TempDir(),
	}
	input.ToolInput.Command = "echo hello"

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output != "" {
		t.Errorf("expected empty output for non-Bash tool, got: %s", output)
	}
}

func TestPreflightHookEmptyCommand(t *testing.T) {
	// Empty command should produce no output (fail open)
	input := preflightHookInput{
		ToolName: "Bash",
		CWD:      t.TempDir(),
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output != "" {
		t.Errorf("expected empty output for empty command, got: %s", output)
	}
}

// capturePreflightHook simulates the hook by redirecting stdin/stdout
// and calling runPreflightHook, then returning captured stdout.
func capturePreflightHook(t *testing.T, inputData []byte) string {
	t.Helper()

	// Create a pipe to simulate stdin
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// Write input and close write end
	if _, err := stdinW.Write(inputData); err != nil {
		t.Fatal(err)
	}
	stdinW.Close()

	// Create a pipe to capture stdout
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	// Swap stdin/stdout
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	os.Stdin = stdinR
	os.Stdout = stdoutW

	// Run the hook
	_ = runPreflightHook()

	// Restore and close
	os.Stdin = oldStdin
	os.Stdout = oldStdout
	stdoutW.Close()

	buf := make([]byte, 4096)
	n, _ := stdoutR.Read(buf)
	stdoutR.Close()
	return string(buf[:n])
}

func TestPreflightHookScriptWithBlockedCommand(t *testing.T) {
	// A script containing a blocked command should produce no output (allow Bash to handle it)
	tmpDir := t.TempDir()

	// Create a script with a blocked command
	scriptPath := filepath.Join(tmpDir, "bundle-mac")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\nsource ./env.sh\necho building\n"), 0755); err != nil {
		t.Fatal(err)
	}

	input := preflightHookInput{
		ToolName: "Bash",
		CWD:      tmpDir,
	}
	input.ToolInput.Command = "./bundle-mac -i"

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output != "" {
		t.Errorf("expected empty output for script with blocked command (should fall through to Bash), got: %s", output)
	}
}

func TestPreflightHookBashScriptWithBlockedCommand(t *testing.T) {
	// bash ./script.sh where script contains blocked commands should produce no output
	tmpDir := t.TempDir()

	scriptPath := filepath.Join(tmpDir, "setup.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/bash\ncurl http://example.com\necho done\n"), 0755); err != nil {
		t.Fatal(err)
	}

	input := preflightHookInput{
		ToolName: "Bash",
		CWD:      tmpDir,
	}
	input.ToolInput.Command = "bash ./setup.sh"

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output != "" {
		t.Errorf("expected empty output for bash script with blocked command, got: %s", output)
	}
}

func TestPreflightHookDangerouslyDisableSandbox(t *testing.T) {
	// A valid command with dangerouslyDisableSandbox should produce no output (allow through)
	input := preflightHookInput{
		ToolName: "Bash",
		CWD:      t.TempDir(),
	}
	input.ToolInput.Command = "echo hello"
	input.ToolInput.DangerouslyDisableSandbox = true

	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	output := capturePreflightHook(t, inputJSON)
	if output != "" {
		t.Errorf("expected empty output when dangerouslyDisableSandbox is true, got: %s", output)
	}
}

func TestConfigurePreflightHook(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// Test with non-existent file
	err := configurePreflightHook(settingsPath, "/usr/local/bin/lite-sandbox")
	if err != nil {
		t.Fatalf("configurePreflightHook failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("failed to read settings.json: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse settings.json: %v", err)
	}

	var hooks map[string][]hookMatcher
	if err := json.Unmarshal(raw["hooks"], &hooks); err != nil {
		t.Fatalf("failed to parse hooks: %v", err)
	}

	preToolUse := hooks["PreToolUse"]
	if len(preToolUse) != 1 {
		t.Fatalf("expected 1 PreToolUse matcher, got %d", len(preToolUse))
	}
	if preToolUse[0].Matcher != "Bash" {
		t.Errorf("expected matcher Bash, got %s", preToolUse[0].Matcher)
	}
	if len(preToolUse[0].Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(preToolUse[0].Hooks))
	}
	if preToolUse[0].Hooks[0].Type != "command" {
		t.Errorf("expected type command, got %s", preToolUse[0].Hooks[0].Type)
	}
	expectedCmd := "/usr/local/bin/lite-sandbox preflight"
	if preToolUse[0].Hooks[0].Command != expectedCmd {
		t.Errorf("expected command %q, got %q", expectedCmd, preToolUse[0].Hooks[0].Command)
	}
}

func TestConfigurePreflightHookPreservesExistingKeys(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// Write settings with existing keys
	existingContent := `{"permissions": {"allow": ["mcp__lite-sandbox__bash"]}, "someOther": true}`
	if err := os.WriteFile(settingsPath, []byte(existingContent), 0644); err != nil {
		t.Fatal(err)
	}

	err := configurePreflightHook(settingsPath, "/usr/local/bin/lite-sandbox")
	if err != nil {
		t.Fatalf("configurePreflightHook failed: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	if _, ok := raw["permissions"]; !ok {
		t.Error("existing key 'permissions' was lost")
	}
	if _, ok := raw["someOther"]; !ok {
		t.Error("existing key 'someOther' was lost")
	}
	if _, ok := raw["hooks"]; !ok {
		t.Error("hooks key was not added")
	}
}

func TestConfigurePreflightHookIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// Run twice
	err := configurePreflightHook(settingsPath, "/usr/local/bin/lite-sandbox")
	if err != nil {
		t.Fatal(err)
	}
	err = configurePreflightHook(settingsPath, "/usr/local/bin/lite-sandbox")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	var hooks map[string][]hookMatcher
	if err := json.Unmarshal(raw["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}

	preToolUse := hooks["PreToolUse"]
	if len(preToolUse) != 1 {
		t.Fatalf("expected 1 PreToolUse matcher, got %d", len(preToolUse))
	}
	if len(preToolUse[0].Hooks) != 1 {
		t.Fatalf("expected 1 hook (idempotent), got %d", len(preToolUse[0].Hooks))
	}
}

func TestConfigurePreflightHookUpdatesExistingPath(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// Install with old path
	err := configurePreflightHook(settingsPath, "/old/path/lite-sandbox")
	if err != nil {
		t.Fatal(err)
	}

	// Install with new path — should add a second hook entry to the matcher
	err = configurePreflightHook(settingsPath, "/new/path/lite-sandbox")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	var hooks map[string][]hookMatcher
	if err := json.Unmarshal(raw["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}

	preToolUse := hooks["PreToolUse"]
	if len(preToolUse) != 1 {
		t.Fatalf("expected 1 matcher, got %d", len(preToolUse))
	}
	// Both old and new should be present
	if len(preToolUse[0].Hooks) != 2 {
		t.Fatalf("expected 2 hooks (old + new path), got %d", len(preToolUse[0].Hooks))
	}
}
