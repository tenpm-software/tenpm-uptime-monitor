package monitor

import (
	"fmt"
	"regexp"
	"sync"
)

// CheckerFactory builds the Checker for a scheme registered with
// RegisterChecker. It is called once for each SchemeChecker constructed, with
// the egress policy that agent runs under, so a checker that dials out can honour
// it (see Policy.pinnedDialer).
type CheckerFactory func(policy Policy) Checker

var (
	registryMu sync.RWMutex
	registry   = map[string]CheckerFactory{}

	// builtinSchemes are handled by SchemeChecker itself and cannot be replaced.
	builtinSchemes = map[string]bool{"http": true, "https": true, "tcp": true, "tls": true}

	// schemeRE is RFC 3986's scheme production, lowercase only: url.Parse
	// lowercases a scheme, so an upper-case registration could never match.
	schemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
)

// RegisterChecker adds a check type to this binary: a check whose URL uses
// scheme (for example "mysql://user@host/db") is executed by the Checker
// factory builds, alongside the built-in http, https, tcp and tls checkers.
//
// It is meant to be called from an init function or the start of main, before
// the agent is started, in a program that imports this package - the way a
// database/sql driver registers itself. Checkers are compiled in, not loaded at
// run time. Like database/sql.Register it panics on a programming error: an
// empty or malformed scheme, a nil factory, a built-in scheme, or a scheme
// registered twice.
//
// Registering has no effect on an agent running with PolicyStrict, the policy
// the shared fleet runs under: no custom checker is built for it and any
// scheme outside http, https, tcp and tls is refused before dispatch. A custom
// check type therefore only ever runs on agents their operator built and runs
// themselves.
//
// A SchemeChecker snapshots the registry when it is created, so register before
// calling NewSchemeChecker/NewSchemeCheckerWithPolicy or Run.
func RegisterChecker(scheme string, factory CheckerFactory) {
	if !schemeRE.MatchString(scheme) {
		panic(fmt.Sprintf("monitor: RegisterChecker: invalid scheme %q (want lowercase letters, digits, +, - and .)", scheme))
	}
	if builtinSchemes[scheme] {
		panic(fmt.Sprintf("monitor: RegisterChecker: scheme %q is built in and cannot be replaced", scheme))
	}
	if factory == nil {
		panic(fmt.Sprintf("monitor: RegisterChecker: nil factory for scheme %q", scheme))
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[scheme]; dup {
		panic(fmt.Sprintf("monitor: RegisterChecker: scheme %q is already registered", scheme))
	}
	registry[scheme] = factory
}

// registeredCheckers builds a Checker from every registered factory for policy.
// Under PolicyStrict it returns none: see RegisterChecker.
func registeredCheckers(policy Policy) map[string]Checker {
	if policy == PolicyStrict {
		return nil
	}
	registryMu.RLock()
	defer registryMu.RUnlock()
	if len(registry) == 0 {
		return nil
	}
	out := make(map[string]Checker, len(registry))
	for scheme, factory := range registry {
		out[scheme] = factory(policy)
	}
	return out
}
