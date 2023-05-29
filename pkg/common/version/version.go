package version

var (
	// Will be overwritten automatically by the build system
	version = "unknown"
)

// GetVersion returns the version of the CLI
func Version() string {
	return version
}
