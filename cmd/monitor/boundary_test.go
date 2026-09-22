package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestAgentDoesNotDependOnTheServer guards the line the agent is published
// along: it must build, and test, without any closed server code and without the
// MySQL driver. Inside this repo's go.work that line is only partly enforced by
// the toolchain: Go's internal/ rule blocks tenpoint/internal/..., but a
// workspace lets the agent import any other package of the server module
// (tenpoint/web, say) without a go.mod requirement, so this test is the real
// guard until the agent is extracted. It also catches the MySQL driver arriving
// by some other route, and covers the public packages' test dependencies, so
// `go test` of them never needs a database.
func TestAgentDoesNotDependOnTheServer(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}

	const module = "github.com/tenpm-software/tenpm-uptime-monitor"
	forbidden := func(pkg string) bool {
		return strings.HasPrefix(pkg, "tenpoint/") || pkg == "github.com/go-sql-driver/mysql"
	}

	for _, args := range [][]string{
		{"list", "-deps", "-f", "{{.ImportPath}}", "."},
		{"list", "-deps", "-test", "-f", "{{.ImportPath}}", module + "/monitor", module + "/model", module + "/internal/migrate"},
	} {
		out, err := exec.Command(goBin, args...).CombinedOutput() // #nosec G204 -- fixed argument lists above, go tool found via LookPath
		if err != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		for _, pkg := range strings.Fields(string(out)) {
			if forbidden(pkg) {
				t.Errorf("go %s: the agent depends on %s", strings.Join(args, " "), pkg)
			}
		}
	}
}
