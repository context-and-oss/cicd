package main

// services.go holds the rules behind a test leg's declared dependency
// services: what a declaration may say, what the leg's command is told about
// it, and — the part this file exists for — what it means when a service did
// not become usable.
//
// Deliberately untagged (no //go:build !unit_test), like testlegs.go and
// coverageglob.go. byotest.go, which does the container work, is tagged and
// unreachable from `go test -tags unit_test`; every long-lived defect in this
// module has lived in a tagged file, so the decisions live here and byotest.go
// only reads bytes and binds containers.
//
// Why any of this exists: quality.Test ran a consumer's command in a container
// with nothing beside it, so a suite with integration tests failed at fixture
// initialisation on every run and the envelope said "test command failed
// (exit 1)". The consumer's remaining option was mounting the runner's Docker
// socket, which hands a consumer-authored command string root on the runner,
// depends on ambient state no envelope can describe, and is refused here.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// serviceInstanceLabel is the OCI label that gives every (leg, alias) pair its
// own service definition. The engine runs one instance per definition and
// shares it with every container binding it, so without this two legs that
// declare the same service would get one database between them — and under
// --parallelism, one database written by two suites at once.
const serviceInstanceLabel = "dev.cicd.test-leg-service"

// serviceInstanceKey is the label's value. Leg labels match [A-Za-z0-9._-] and
// aliases are hostnames, so neither can contain the slash and no two pairs
// share a key.
func serviceInstanceKey(legLabel, alias string) string {
	return legLabel + "/" + alias
}

// serviceLimit caps how many services one leg may declare.
//
// Per leg, not per run: testLegLimit already bounds the legs at 8, so this
// bounds the product at 32 containers, each of which is its own image pull and
// its own healthcheck wait before the leg's command may start. A leg needing a
// fifth backing service is describing an environment rather than a test
// fixture, and the right shape for that is a deployed target and the DAST
// composite.
//
// Over the limit is an error, never a truncated list — the testLegLimit
// precedent. Binding three of four services and running the command is how a
// suite fails against a missing dependency while the evidence says the leg ran.
const serviceLimit = 4

// maxServiceAliasLen bounds an alias at the DNS label limit. The alias is the
// hostname the engine binds, so the limit is not ours to choose.
const maxServiceAliasLen = 63

// defaultReadyTimeoutSeconds is the budget a declared readyCmd gets when the
// leg names none.
const defaultReadyTimeoutSeconds = 60

// maxReadyTimeoutSeconds bounds that budget. A readiness loop is a pipeline
// holding a container open and doing nothing; past five minutes the honest
// report is that the dependency does not start, not that cicd should keep
// waiting for it.
const maxReadyTimeoutSeconds = 300

// The two values serviceReport.ReadyVia may take. They are not decoration: the
// same `ready: true` means different things in the two paths, and a reader who
// cannot tell them apart has the weaker claim without knowing it.
const (
	// readyViaEngine means the engine's own healthcheck let the dependent
	// container start — the declared port accepted a connection. That is a
	// floor, not a verdict: a database process that is listening and still
	// replaying its write-ahead log answers the socket and refuses the query.
	readyViaEngine = "engine-healthcheck"
	// readyViaCmd means a consumer-declared readyCmd exited 0, which is the
	// only claim about readiness that cicd did not invent.
	readyViaCmd = "ready-cmd"
)

// serviceSpec is one dependency a leg declares: a throwaway container the
// engine binds beside the leg's own, reachable at Alias.
//
// There is deliberately no command or entrypoint field. The image's own
// entrypoint is what a stock postgres/redis/mssql image exists to provide, and
// a second way to say it is a drift waiting to happen — the reasoning testLeg
// gives for having no working-directory field.
//
// There is deliberately no secretEnv either. A Dagger secret cannot travel
// inside a JSON string parameter without being a plaintext credential in the
// pipeline's own configuration first, so offering the field would be offering
// the thing this repository refuses.
type serviceSpec struct {
	// Alias is the hostname the leg's command resolves, and the fragment the
	// injected environment variables are named after. It is the service's
	// identity in the evidence, so renaming it renames it in the next run's
	// evidence too.
	Alias string `json:"alias"`
	// Image is the container image, passed through verbatim. It is the
	// consumer's image, which ADR-004 level 3 leaves the consumer to pin;
	// cicd pins the images it selects on its own behalf and not this one.
	Image string `json:"image"`
	// Port is the port the service listens on and the engine gates the leg's
	// container against.
	//
	// Required, with no default. A guessed 5432 is a binding that looks
	// configured: the leg would start against a service that is listening on
	// something else, and fail in the consumer's own fixture code, which is
	// the failure this whole file exists to stop reporting as a broken test.
	Port int `json:"port"`
	// Env is handed to the service container as plain environment variables.
	// Only the key names reach the envelope; see serviceReport.EnvKeys.
	Env map[string]string `json:"env,omitempty"`
	// ReadyCmd is an optional consumer-declared readiness check, run in the
	// pinned alpine image beside the service until it exits 0. Empty means the
	// engine's port gate is the whole claim, and the evidence says so.
	ReadyCmd string `json:"readyCmd,omitempty"`
	// ReadyTimeout is the budget for ReadyCmd, in seconds. Meaningless without
	// ReadyCmd, and refused there rather than ignored.
	ReadyTimeout int `json:"readyTimeout,omitempty"`
}

// serviceKeys is the accepted key set for a service object, shared with the
// case-exact check parseAppLegs runs. One list, because three statements of
// one key set is how `.slnx` went missing from two of three marker copies.
var serviceKeys = []string{"alias", "image", "port", "env", "readyCmd", "readyTimeout"}

// validateServices checks one leg's declared services. legRef is how the leg
// is named in a rejection ("test-legs[2] (dotnet)"), so the caller owns the
// wording of its own index.
func validateServices(legRef string, svcs []serviceSpec) error {
	if len(svcs) == 0 {
		return nil
	}
	if len(svcs) > serviceLimit {
		return fmt.Errorf(
			"%s: %d services exceeds the limit of %d — each service is its own image pull and its own healthcheck wait before the command may start, and binding only some of them while running the command is how a suite fails against a missing dependency under evidence that says the leg ran",
			legRef, len(svcs), serviceLimit)
	}

	seenAlias := map[string]bool{}
	seenEnvPrefix := map[string]string{}
	for i := range svcs {
		svc := &svcs[i]
		svc.Alias = strings.TrimSpace(svc.Alias)
		svc.Image = strings.TrimSpace(svc.Image)
		svc.ReadyCmd = strings.TrimSpace(svc.ReadyCmd)

		if svc.Alias == "" {
			return fmt.Errorf("%s services[%d]: alias must not be empty — it is the hostname the leg resolves and the name this service carries in the evidence", legRef, i)
		}
		if !validServiceAlias(svc.Alias) {
			return fmt.Errorf(
				"%s services[%d]: alias %q must be 1-%d characters of lowercase letters, digits and dashes, starting with a letter and ending alphanumeric — the alias is bound as a hostname and is upper-cased into an environment variable name, and neither tolerates the dots, underscores or capitals a leg label may carry",
				legRef, i, svc.Alias, maxServiceAliasLen)
		}
		if seenAlias[svc.Alias] {
			return fmt.Errorf("%s services[%d]: alias %q is declared twice — one hostname cannot answer for two services", legRef, i, svc.Alias)
		}
		seenAlias[svc.Alias] = true

		// Two aliases that differ but name one environment variable would have
		// one silently overwrite the other, and the leg would connect to
		// whichever cicd happened to inject last. validServiceAlias makes that
		// unreachable today; this check is what keeps it unreachable if the
		// charset is ever widened, which is the change that would reintroduce it.
		prefix := serviceEnvPrefix(svc.Alias)
		if prev, clash := seenEnvPrefix[prefix]; clash {
			return fmt.Errorf("%s services[%d]: aliases %q and %q both name the environment variables %s_HOST and %s_PORT — one would silently overwrite the other", legRef, i, prev, svc.Alias, prefix, prefix)
		}
		seenEnvPrefix[prefix] = svc.Alias

		if svc.Image == "" {
			return fmt.Errorf("%s services[%d] (%s): image must not be empty", legRef, i, svc.Alias)
		}
		if strings.ContainsAny(svc.Image, " \t\n\r") {
			return fmt.Errorf("%s services[%d] (%s): image %q must be a single image reference", legRef, i, svc.Alias, svc.Image)
		}
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf(
				"%s services[%d] (%s): port must be declared, between 1 and 65535 — cicd does not guess a port, because a guessed one is a binding that looks configured while the leg connects to nothing",
				legRef, i, svc.Alias)
		}
		for key := range svc.Env {
			if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "= \t\n\r\x00") {
				return fmt.Errorf("%s services[%d] (%s): env key %q is not a usable environment variable name", legRef, i, svc.Alias, key)
			}
		}
		if svc.ReadyCmd == "" && svc.ReadyTimeout != 0 {
			return fmt.Errorf(
				"%s services[%d] (%s): readyTimeout is the budget for readyCmd and this service declares none — the engine's port gate has its own budget, which cicd does not set, so this value would be silently ignored",
				legRef, i, svc.Alias)
		}
		if svc.ReadyCmd != "" {
			if svc.ReadyTimeout == 0 {
				svc.ReadyTimeout = defaultReadyTimeoutSeconds
			}
			if svc.ReadyTimeout < 1 || svc.ReadyTimeout > maxReadyTimeoutSeconds {
				return fmt.Errorf("%s services[%d] (%s): readyTimeout %d is not between 1 and %d seconds", legRef, i, svc.Alias, svc.ReadyTimeout, maxReadyTimeoutSeconds)
			}
		}
	}
	return nil
}

// validServiceAlias reports whether alias is a usable DNS label.
//
// Stricter than validLegLabel on purpose, and the extra strictness is not
// taste. A leg label is rendered into prose; an alias is resolved as a
// hostname and upper-cased into an environment variable name, so a dot makes
// it look like a subdomain, an underscore is not a legal hostname character,
// and `DB` beside `db` is two aliases the engine cannot tell apart.
func validServiceAlias(alias string) bool {
	if alias == "" || len(alias) > maxServiceAliasLen {
		return false
	}
	for i, r := range alias {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		case r == '-':
			if i == 0 || i == len(alias)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// serviceEnvPrefix is the environment-variable stem for one alias.
//
// The leg's command needs something deterministic to read, and "the alias is
// the hostname" is only deterministic to someone who read this file. Two
// variables per service, named after the alias, is a rule a consumer can apply
// without asking.
func serviceEnvPrefix(alias string) string {
	var b strings.Builder
	b.WriteString("CICD_SERVICE_")
	for _, r := range strings.ToUpper(alias) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// serviceEnvVars is what one bound service adds to the leg's environment, as
// ordered name/value pairs so the injection order is the declaration order.
func serviceEnvVars(svc serviceSpec) [][2]string {
	prefix := serviceEnvPrefix(svc.Alias)
	return [][2]string{
		{prefix + "_HOST", svc.Alias},
		{prefix + "_PORT", strconv.Itoa(svc.Port)},
	}
}

// serviceReport is one declared service's record in the leg's report.
//
// The env *values* are deliberately absent, and only the key names are kept.
// It is the rule legReport already states for the leg's command — consumer
// authored text that can carry a credential inline — arriving one field over:
// a service's env map is where a test database password is written, and this
// repository does not let a credential reach an envelope. The key names are
// what makes the record useful, because they say what the service was
// configured with without saying what it was configured to.
type serviceReport struct {
	Alias string `json:"alias"`
	Image string `json:"image"`
	Port  int    `json:"port"`
	// EnvKeys are the declared env key names, sorted. Sorted because a Go map
	// iterates in a random order and two runs over one declaration must not
	// produce two different envelopes.
	EnvKeys []string `json:"envKeys,omitempty"`
	// Ready is whether this service became usable. False is a non-run for the
	// leg, not a failed test.
	Ready bool `json:"ready"`
	// ReadyVia names which claim Ready is making. See readyViaEngine.
	ReadyVia string `json:"readyVia,omitempty"`
	// WaitedSeconds is how long a declared readyCmd waited. Nil when no
	// readyCmd ran: a zero there would say the service was ready immediately,
	// which is a measurement nobody took.
	WaitedSeconds *int `json:"waitedSeconds,omitempty"`
	// ReadyAttempts is how many times a declared readyCmd was run. Nil for the
	// same reason.
	ReadyAttempts *int `json:"readyAttempts,omitempty"`
	// Error is why this service is not ready, scrubbed. Empty when it is.
	Error string `json:"error,omitempty"`
}

// serviceProbe is what the attribution container reported about one service.
// Every field is raw: byotest.go reads bytes and an error out of the engine,
// and foldServiceProbe is the one place that decides what they mean.
type serviceProbe struct {
	// BindErr is the engine's own answer. It is set when the probe container
	// bound to this one service could not complete — which, for a service
	// whose declared port never accepts a connection, is where the engine's
	// healthcheck failure lands.
	BindErr error
	// ReadyRan is whether a declared readyCmd's loop container completed at
	// all. False with a declared readyCmd is a non-run of the check itself.
	ReadyRan bool
	// ReadyStatus, ReadyAttempts and ReadyWaited are the three files the
	// readiness loop wrote, unparsed.
	ReadyStatus   string
	ReadyAttempts string
	ReadyWaited   string
	// ReadyReadErr is why the status file could not be read, when it could not.
	ReadyReadErr error
	// ReadyCountersErr is why the two counter files could not be read, when
	// the status could. The verdict stands — it is the status — and the row
	// says its counters were not measured and why, rather than nothing.
	ReadyCountersErr error
}

// foldServiceProbe turns one service's raw probe into its evidence row and, if
// it is not usable, the one sentence that says so. The third value is a
// warning: a disclosure about the row that changes no verdict.
//
// The sentences are returned separately because they belong in errors[] and
// warnings[]: cross-cutting/evidence drops genericReport, so a record only in
// the row would never reach combined-evidence.json or the pull request
// comment, which is the only place most consumers will ever read this.
//
// A service that did not become usable is an error and never a warning. The
// consumer runs --fail-on NONE, where gatedPassed suppresses a findings
// verdict and cannot suppress a non-run, so a warning here would be a
// dependency that silently was not there under a green tick — the founding
// failure of this repository, arriving through the newest door.
func foldServiceProbe(svc serviceSpec, p serviceProbe) (serviceReport, string, string) {
	rep := serviceReport{
		Alias:   svc.Alias,
		Image:   svc.Image,
		Port:    svc.Port,
		EnvKeys: sortedEnvKeys(svc.Env),
	}

	if p.BindErr != nil {
		detail, _ := scrubCredentials(p.BindErr.Error())
		rep.Error = fmt.Sprintf(
			"service %s (%s) never became usable on port %d: %s. The leg's command did not run, so this is a non-run rather than a failing test — at every threshold, NONE included.",
			svc.Alias, svc.Image, svc.Port, oneLine(detail))
		return rep, rep.Error, ""
	}

	if svc.ReadyCmd == "" {
		// The engine let a container bound to this service start, which is the
		// whole claim and is worth stating as such.
		rep.Ready = true
		rep.ReadyVia = readyViaEngine
		return rep, "", ""
	}

	if !p.ReadyRan || p.ReadyReadErr != nil {
		detail := "the readiness container produced no result"
		if p.ReadyReadErr != nil {
			scrubbed, _ := scrubCredentials(p.ReadyReadErr.Error())
			detail = oneLine(scrubbed)
		}
		rep.ReadyVia = readyViaCmd
		rep.Error = fmt.Sprintf(
			"service %s (%s): the declared readiness check could not be run: %s. cicd does not fall back to the engine's port gate here, because a check that was asked for and not performed is not a check that passed.",
			svc.Alias, svc.Image, detail)
		return rep, rep.Error, ""
	}

	// The counters are disclosure, not verdict: nil is "not measured", and when
	// the reason is a read cicd could not perform, the reason is said in the
	// warning rather than left looking like a probe that never counted.
	var warning string
	attempts, waited := atoiPtr(p.ReadyAttempts), atoiPtr(p.ReadyWaited)
	if p.ReadyCountersErr != nil {
		attempts, waited = nil, nil
		scrubbed, _ := scrubCredentials(p.ReadyCountersErr.Error())
		warning = fmt.Sprintf("service %s (%s): the readiness check's attempt and wait counters could not be read back from the container (%s); the check's verdict stands, its counters are not measured",
			svc.Alias, svc.Image, oneLine(scrubbed))
	}
	rep.ReadyAttempts, rep.WaitedSeconds = attempts, waited
	rep.ReadyVia = readyViaCmd

	if strings.TrimSpace(p.ReadyStatus) == "0" {
		rep.Ready = true
		return rep, "", warning
	}

	rep.Error = fmt.Sprintf(
		"service %s (%s): the declared readiness check never succeeded within %ds (%s, last exit %s). The port may well have been open — the engine let a container start against it — which is why an unanswered readiness check is reported and not silently replaced by that weaker claim.",
		svc.Alias, svc.Image, svc.ReadyTimeout, describeAttempts(attempts, waited), strings.TrimSpace(p.ReadyStatus))
	return rep, rep.Error, warning
}

// describeAttempts renders the two loop counters for prose, without pretending
// to numbers the probe did not report.
func describeAttempts(attempts, waited *int) string {
	switch {
	case attempts != nil && waited != nil:
		return fmt.Sprintf("%d attempts over %ds", *attempts, *waited)
	case attempts != nil:
		return fmt.Sprintf("%d attempts", *attempts)
	case waited != nil:
		return fmt.Sprintf("%ds elapsed", *waited)
	}
	return "attempts not counted"
}

// sortedEnvKeys lists an env map's key names, sorted, values discarded.
func sortedEnvKeys(env map[string]string) []string {
	if len(env) == 0 {
		return nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// atoiPtr parses one of the probe's counter files, or reports that it could
// not. Nil is "not measured", which is a different statement from zero.
func atoiPtr(raw string) *int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	return &n
}

// oneLine flattens a message for a single-line errors[] entry.
//
// It also strips backticks. Every string here carries a consumer-authored
// alias or image reference and lands in a markdown table cell in the pull
// request comment; notify's codeSpan fences what it is given a span for, and
// nothing fences a bare sentence — the legscope_test.go rule.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return "no detail reported"
	}
	return s
}

// serviceReadyScript polls a declared readyCmd until it exits 0 or the budget
// runs out, and records the outcome in three files.
//
// It runs in a fresh container built from the *service's own image*, bound to
// the service over the network — not in the pinned alpine the attribution probe
// uses. That is a deliberate split, and it is not the weakening it resembles.
// The readiness commands consumers actually write are the client tools that
// ship beside the server: pg_isready, redis-cli ping, mysqladmin ping. None of
// them exists in alpine, so a readyCmd that had to run there could express
// almost nothing beyond `nc -z`, which is the engine's port gate spelled out by
// hand — the claim this field exists to improve on. The container is a client
// talking to the service across a binding, so the service still cannot vouch
// for itself; what it supplies is the client binary. The attribution probe
// stays in pinned alpine precisely so the *bind* verdict never depends on a
// consumer image having a shell.
//
// The shape is probeReadiness's (src/security/web.go), and so is the reason it
// ends `exit 0`: this container's own exit status must not be the answer,
// because a failing readiness check is a result to be read out of the files,
// not an exec the engine reports as broken. The distinction is the whole
// subject of this module.
const serviceReadyScript = `set -u
cmd="$1"
deadline="$2"
attempts=0
started=$(date +%s)
status=1
while :; do
  attempts=$((attempts + 1))
  if sh -c "$cmd" >/tmp/svc.last 2>&1; then status=0; break; fi
  status=$?
  now=$(date +%s)
  if [ $((now - started)) -ge "$deadline" ]; then break; fi
  sleep 2
done
now=$(date +%s)
echo "$status" > /tmp/svc.status
echo "$attempts" > /tmp/svc.attempts
echo $((now - started)) > /tmp/svc.waited
exit 0`

// servicesSummary is the line a leg adds when at least one of its services is
// ready on the engine's port gate alone.
//
// That condition is the whole point of the line. `ready: true` via
// readyViaEngine means a socket accepted a connection, which a database still
// replaying its write-ahead log will also do — so the claim is a floor and the
// evidence has to say so in words, not only in a field named readyVia that a
// reader has to already understand.
//
// Silent otherwise, and silent on every leg that declares no services. A leg
// whose services all passed a declared readiness check has nothing to disclose:
// the strongest available claim was made. A disclosure on every run is noise,
// and noise is what gets a line ignored on the run that mattered — the
// build.NoArtifact rule, and the reason scripts/smoke/commit-shapes.sh asserts
// that warning's absence for the other two shapes.
func servicesSummary(legRef string, reports []serviceReport) string {
	var floors []string
	for _, r := range reports {
		if r.Ready && r.ReadyVia == readyViaEngine {
			floors = append(floors, fmt.Sprintf("%s (%s, port %d)", r.Alias, r.Image, r.Port))
		}
	}
	if len(floors) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"%s: %s answered on the declared port and nothing else was checked. An open socket is not a dependency that is ready — a database still recovering accepts the connection and refuses the query — so a test that fails against one of these is not necessarily a test that is wrong. Declare readyCmd on the service to have cicd wait for a check you choose.",
		legRef, strings.Join(floors, ", "))
}

// checkServiceKeyCase rejects a service key that differs from the declared one
// only in case.
//
// encoding/json matches a field name case-insensitively, and
// DisallowUnknownFields refuses only a key that matches no field at all — so
// "readycmd" reaches ReadyCmd and the strict decoder says nothing. That is
// tolerable for a key this module owns end to end, and it is not tolerable
// here: app mode's parseAppLegs checks the same document case-exactly, so a
// spelling this module accepts and that one refuses is one configuration
// producing two verdicts depending on which composite reads it. The corpus in
// testdata/leg-service-documents.json is what both sides answer, and it is
// what found this.
//
// Scoped to service objects on purpose. The leg's own keys have been reachable
// under any casing since --test-legs shipped, and tightening them is a
// breaking change that belongs to its own decision, not to this one.
func checkServiceKeyCase(raw string) error {
	var records []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		// The strict decoder has already read this document and accepted it;
		// anything unparseable here is cicd's own defect, not the consumer's.
		return fmt.Errorf("test-legs: re-reading the document to check service key spelling failed: %w", err)
	}
	known := map[string]bool{}
	for _, k := range serviceKeys {
		known[k] = true
	}
	for i, record := range records {
		nested, ok := record["services"]
		if !ok {
			continue
		}
		var svcs []map[string]json.RawMessage
		if err := json.Unmarshal(nested, &svcs); err != nil {
			return fmt.Errorf("test-legs[%d]: services: %w", i, err)
		}
		for j, svc := range svcs {
			for key := range svc {
				if !known[key] {
					return fmt.Errorf(
						"test-legs[%d]: services[%d]: unknown field %q — a service object takes %s, spelled exactly; a key that differs only in case is refused rather than quietly accepted, because the commit composite reads the same document case-exactly",
						i, j, key, strings.Join(serviceKeys, ", "))
				}
			}
		}
	}
	return nil
}
