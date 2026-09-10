// Package version holds build metadata. Both values are variables, not
// constants, because GoReleaser injects them at link time with
// -X github.com/aspex-security/aspex/internal/version.Version=...; -X cannot
// set a const, and when these were consts every release silently reported the
// value hardcoded here and "built dev".
package version

// Version is the semantic version. Overridden by GoReleaser from the git tag.
var Version = "0.6.1"

// BuildDate is the release build date. Overridden by GoReleaser.
var BuildDate = "dev"
