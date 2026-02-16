package bash_sandboxed

import "github.com/gartnera/lite-sandbox-mcp/config"

// newTestSandbox returns a Sandbox with no extra commands for use in tests.
// By default, git permissions use defaults (local_read=true, local_write=true,
// remote_read=true, remote_write=false).
func newTestSandbox() *Sandbox {
	return NewSandbox()
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

// newTestSandboxWithGitConfig returns a Sandbox configured with the given GitConfig.
func newTestSandboxWithGitConfig(gitCfg *config.GitConfig) *Sandbox {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{Git: gitCfg})
	return s
}
