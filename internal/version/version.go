// Package version holds the agent's build version string, injected at release
// time via -ldflags
// "-X github.com/tenpm-software/tenpm-uptime-monitor/internal/version.Version=<value>"
// (see the Makefile's release-agent target). Local builds report "dev".
package version

var Version = "dev"
