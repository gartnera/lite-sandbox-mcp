package bash_sandboxed

// newTestSandbox returns a Sandbox with no extra commands for use in tests.
func newTestSandbox() *Sandbox {
	return NewSandbox()
}
