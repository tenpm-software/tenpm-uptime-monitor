package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tenpm-software/tenpm-uptime-monitor/internal/migrate"
	"github.com/tenpm-software/tenpm-uptime-monitor/internal/version"
	"github.com/tenpm-software/tenpm-uptime-monitor/model"
	"github.com/tenpm-software/tenpm-uptime-monitor/monitor"

	_ "modernc.org/sqlite"
)

// runTestCheck implements -test-check: read check definitions, run them through
// the very same checker the daemon uses, print the capture, and return an exit
// code. Non-zero when any check failed, so this can gate a provisioning script.
func runTestCheck(path string, policy monitor.Policy) int {
	in := os.Stdin
	if path != "-" {
		f, err := os.Open(path) // #nosec G304 -- path is a CLI flag/env var the operator supplies themselves, not attacker input
		if err != nil {
			fmt.Fprintf(os.Stderr, "test-check: %v\n", err)
			return 2
		}
		defer f.Close()
		in = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), monitor.TestCheckTimeout)
	defer cancel()

	checker := monitor.NewSchemeCheckerWithPolicy(policy)
	failed, err := monitor.TestChecksFromJSON(ctx, checker, in, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "test-check: %v\n", err)
		return 2
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// runImportPrivateCheck implements -import-private-check: read the check
// definition(s) in path (the same JSON shape -test-check reads, and the
// server's own export produces), and persist their content into the local
// database, keyed by guid. Unlike -test-check, this needs the database - it
// is writing into it, not running anything - but nothing else the daemon
// needs: no server, no enrollment, no name (private-checks-design.md
// decision 3, "no new monitor-side authoring surface, reuses what already
// exists").
func runImportPrivateCheck(path, dbPath string) int {
	in := os.Stdin
	if path != "-" {
		f, err := os.Open(path) // #nosec G304 -- path is a CLI flag/env var the operator supplies themselves, not attacker input
		if err != nil {
			fmt.Fprintf(os.Stderr, "import-private-check: %v\n", err)
			return 2
		}
		defer f.Close()
		in = f
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxImportPrivateCheckJSON))
	if err != nil {
		fmt.Fprintf(os.Stderr, "import-private-check: read check definition: %v\n", err)
		return 2
	}
	checks, err := monitor.ParseCheckDefinitions(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import-private-check: %v\n", err)
		return 2
	}
	if len(checks) == 0 {
		fmt.Fprintln(os.Stderr, "import-private-check: no checks in the input")
		return 2
	}
	for _, c := range checks {
		if c.GUID == "" {
			fmt.Fprintf(os.Stderr, "import-private-check: %q has no guid - export it from the server first\n", displayImportName(c))
			return 2
		}
	}

	db, err := migrate.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import-private-check: open database: %v\n", err)
		return 2
	}
	defer db.Close()
	if err := migrate.Apply(db, monitor.Migrations()); err != nil {
		fmt.Fprintf(os.Stderr, "import-private-check: apply migrations: %v\n", err)
		return 2
	}

	store := monitor.NewStore(db)
	for _, c := range checks {
		if err := store.ImportPrivateCheck(c); err != nil {
			fmt.Fprintf(os.Stderr, "import-private-check: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stdout, "imported %s (%s)\n", displayImportName(c), c.GUID)
	}
	return 0
}

// maxImportPrivateCheckJSON mirrors -test-check's own cap: a check
// definition is a few hundred bytes, this just stops a mistyped path at a
// device file from reading forever.
const maxImportPrivateCheckJSON = 1 << 20

func displayImportName(c model.Check) string {
	if c.Name != "" {
		return c.Name
	}
	return "(unnamed)"
}

// runExportChecks implements both -list-checks and -export-private-checks:
// read this agent's local mirror and print it as JSON, in the same shape
// -import-private-check reads back. Like -import-private-check, this
// persists nothing new but does need -db, and needs nothing else the daemon
// requires - no server, no enrollment, no name.
//
// onlyPrivate selects which of Store's two listing methods runs:
// ListAllChecks (-list-checks, unfiltered - see that method's doc comment
// for why no restricted/unrestricted distinction applies to a private
// monitor's own mirror even in principle) or ListPrivateChecks
// (-export-private-checks, locally_defined = 1 only - the checks this agent
// is the sole source of truth for, per private-checks-design.md's "Where
// this stands" on this command).
func runExportChecks(dbPath string, onlyPrivate bool) int {
	db, err := migrate.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "export checks: open database: %v\n", err)
		return 2
	}
	defer db.Close()
	if err := migrate.Apply(db, monitor.Migrations()); err != nil {
		fmt.Fprintf(os.Stderr, "export checks: apply migrations: %v\n", err)
		return 2
	}

	store := monitor.NewStore(db)
	var checks []model.Check
	if onlyPrivate {
		checks, err = store.ListPrivateChecks()
	} else {
		checks, err = store.ListAllChecks()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "export checks: %v\n", err)
		return 2
	}

	exported := make([]monitor.CheckExport, len(checks))
	for i, c := range checks {
		exported[i] = monitor.CheckExportOf(c)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(exported); err != nil {
		fmt.Fprintf(os.Stderr, "export checks: %v\n", err)
		return 2
	}
	return 0
}

func main() {
	showVersion := flag.Bool("version", false, "print the build version and exit")
	serverURL := flag.String("server-url", os.Getenv("SERVER_URL"), "base URL of the central server")
	enrollmentToken := flag.String("enrollment-token", os.Getenv("ENROLLMENT_TOKEN"),
		"an enrollment token from the server's \"Add a monitor\" page; only needed until the first successful enrollment")
	monitorID := flag.String("id", os.Getenv("MONITOR_ID"),
		"leave empty to enroll as a new monitor and let the server mint an id. Set it to re-adopt an existing monitor after its enrollment was reset, when this agent's database was lost too (the id shown on the server's Monitors page) - refused if this agent's own enrollment token does not already own that id. Enrolling with a platform token (the shared fleet) additionally accepts a brand-new, human-chosen id here, e.g. \"edge-01\", instead of a server-minted one - not available when enrolling into a single organisation")
	monitorName := flag.String("name", os.Getenv("MONITOR_NAME"), "human-readable name for this monitor, e.g. \"Sydney home box\"")
	region := flag.String("region", os.Getenv("REGION"), "region, e.g. apac")
	country := flag.String("country", os.Getenv("COUNTRY"), "country code, e.g. AU")
	city := flag.String("city", os.Getenv("CITY"), "city, e.g. Sydney")
	dbPath := flag.String("db", envOr("DB_PATH", "monitor.db"), "path to the monitor SQLite database file")
	syncIntervalSec := flag.Int("sync-interval", envInt("SYNC_INTERVAL_SEC", 45), "seconds between check-sync polls")
	reportIntervalSec := flag.Int("report-interval", envInt("REPORT_INTERVAL_SEC", 45), "seconds between result-upload attempts")
	probeTargets := flag.String("probe-targets", os.Getenv("PROBE_TARGETS"), "comma-separated host:port endpoints dialed to verify internet connectivity (default: Cloudflare, Google, and Quad9 anycast)")
	maxConcurrentChecks := flag.Int("max-concurrent-checks", envInt("MAX_CONCURRENT_CHECKS", monitor.DefaultRunnerConcurrency),
		"maximum number of checks this agent runs at the same time; raise on capable hardware with many checks, lower on constrained devices with a low open-file limit")
	egressPolicy := flag.String("egress-policy", envOr("EGRESS_POLICY", "open"),
		"\"open\" (default) for an agent on your own hardware, or \"strict\" for one running on shared infrastructure: http(s)/tcp only, and no private, loopback, link-local or otherwise internal addresses")
	proxyURLFlag := flag.String("proxy-url", envOr("PROXY_URL", ""),
		"proxy this agent uses to reach the central server (enroll/sync/report) and for its own connectivity check - never used for the checks themselves, which always dial their targets directly. http://, https://, or socks5://host:port, optionally with userinfo for proxy auth. Empty (default) means no proxy")
	logLevel := flag.String("log-level", envOr("LOG_LEVEL", "info"), "minimum log level: debug, info, warn, or error")
	testCheck := flag.String("test-check", "",
		"run the check(s) in this JSON file once, print what came back, and exit - \"-\" reads stdin. For trying a check against something only this machine can reach; needs no enrollment and no server")
	importPrivateCheck := flag.String("import-private-check", "",
		"load the private definition(s) in this JSON file into the local database (-db) and exit - \"-\" reads stdin. For a check the server was deliberately never given the definition of; needs no enrollment and no server, but does need -db")
	listChecks := flag.Bool("list-checks", false,
		"print every check currently mirrored in the local database (-db), full definitions included - the same content -export-private-checks prints, plus everything else this agent holds - as JSON, and exit. Needs no enrollment and no server")
	exportPrivateChecks := flag.Bool("export-private-checks", false,
		"print only the checks this agent holds a definition for that the server was never given (-db), as JSON, and exit - a backup/audit copy, in the same shape -import-private-check reads back. Needs no enrollment and no server")
	flag.Parse()

	// -version short-circuits everything below, even -test-check/-db et al.
	// below - no config validation, no database, no server. That's the
	// whole point of a version check: it has to work regardless of what
	// else is or isn't configured on this box.
	if *showVersion {
		fmt.Println(version.Version)
		os.Exit(0)
	}

	logger, levelErr := newLogger(*logLevel)
	if levelErr != nil {
		logger.Warn("invalid log level, using info", "log_level", *logLevel)
	}

	policy, err := monitor.ParsePolicy(*egressPolicy)
	if err != nil {
		// Deliberately fatal rather than defaulting to open: a typo here on a
		// shared monitor would silently remove the restriction that is the
		// entire reason the flag exists.
		logger.Error("invalid egress policy", "error", err)
		os.Exit(1)
	}
	if policy == monitor.PolicyStrict {
		logger.Info("strict egress policy in effect: http(s)/tcp only, public addresses only")
	}

	proxyURL, err := monitor.ParseProxyURL(*proxyURLFlag)
	if err != nil {
		// Fatal rather than silently unproxied, same reasoning as the egress
		// policy above: a typo here should fail startup loudly, not quietly
		// leave an agent that was meant to reach the server through a proxy
		// unable to reach it at all.
		logger.Error("invalid proxy url", "error", err)
		os.Exit(1)
	}

	if *maxConcurrentChecks <= 0 {
		// NewRunner would quietly fall back to DefaultRunnerConcurrency for
		// any value <= 0; failing fast here instead surfaces a config
		// mistake (e.g. a bad MAX_CONCURRENT_CHECKS) rather than silently
		// running with a different concurrency than the operator asked for.
		logger.Error("max-concurrent-checks must be a positive integer", "value", *maxConcurrentChecks)
		os.Exit(1)
	}

	// -test-check runs one check and exits, before any of the daemon's
	// requirements apply: no server URL, no name, no database, no enrollment.
	// The point is to try a check on the machine that will run it - typically
	// against something the server cannot reach at all - so demanding a working
	// enrollment first would defeat it.
	if *testCheck != "" {
		os.Exit(runTestCheck(*testCheck, policy))
	}

	// -import-private-check persists rather than runs, so it needs -db - but
	// nothing else the daemon requires, for the same reason -test-check
	// doesn't: this is meant to work standalone, before this agent has ever
	// enrolled (private-checks-design.md decision 4, "import works before
	// any sync").
	if *importPrivateCheck != "" {
		os.Exit(runImportPrivateCheck(*importPrivateCheck, *dbPath))
	}

	// -list-checks and -export-private-checks are read-only siblings of
	// -import-private-check: same standalone requirements (-db, nothing
	// else), same short-circuit placement. A user could in principle pass
	// both flags; -list-checks (the superset) wins, since there is no
	// sensible way to print two answers to one invocation and returning the
	// bigger one is the least surprising choice.
	if *listChecks {
		os.Exit(runExportChecks(*dbPath, false))
	}
	if *exportPrivateChecks {
		os.Exit(runExportChecks(*dbPath, true))
	}

	// id is deliberately not in this list: it is the server's to mint, and an
	// agent that supplies one is asking to re-adopt a specific existing
	// monitor.
	if *serverURL == "" || *monitorName == "" || *region == "" || *country == "" || *city == "" {
		logger.Error("server-url, name, region, country, and city are all required")
		os.Exit(1)
	}

	db, err := migrate.Open(*dbPath)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := migrate.Apply(db, monitor.Migrations()); err != nil {
		logger.Error("apply migrations", "error", err)
		os.Exit(1)
	}

	store := monitor.NewStore(db)

	cfg := monitor.Config{
		ServerURL:           *serverURL,
		EnrollmentToken:     *enrollmentToken,
		MonitorID:           *monitorID,
		MonitorName:         *monitorName,
		Region:              *region,
		Country:             *country,
		City:                *city,
		SyncInterval:        time.Duration(*syncIntervalSec) * time.Second,
		ReportInterval:      time.Duration(*reportIntervalSec) * time.Second,
		EgressPolicy:        policy,
		ProbeTargets:        splitCSV(*probeTargets),
		MaxConcurrentChecks: *maxConcurrentChecks,
		ProxyURL:            proxyURL,
	}

	logger.Info("monitor starting", "version", version.Version, "server_url", *serverURL, "name", *monitorName, "db", *dbPath, "proxy_url", redactProxyURL(proxyURL))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := monitor.Run(ctx, cfg, store, logger); err != nil {
		logger.Error("monitor run", "error", err)
		os.Exit(1)
	}

	logger.Info("monitor shut down")
}

// newLogger builds the process logger at the given minimum level. An
// unparseable level falls back to info with a non-nil error rather than
// exiting, so a config typo can't take the monitor down.
func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	err := l.UnmarshalText([]byte(level))
	if err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l})), err
}

// splitCSV parses a comma-separated list, dropping empty entries so ""
// yields nil (which means "use the defaults" to the connectivity gate).
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// redactProxyURL strips userinfo (proxy auth) from a proxy URL so the
// startup line can name it without putting a credential in the logs, same
// reasoning as cmd/server's redactDSN. "none" when no proxy is configured.
func redactProxyURL(u *url.URL) string {
	if u == nil {
		return "none"
	}
	redacted := *u
	redacted.User = nil
	return redacted.String()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
