//go:build unit_test

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The consumer this exists for runs --fail-on NONE. At that threshold a failing
// test is suppressed and a non-run is not, so "the database was never there"
// has to arrive as the second thing. Both halves are asserted together,
// because the error sentence is worthless if the gate still passes.
func TestServiceInstanceKeyIsDistinctPerLegAndAlias(t *testing.T) {
	// The key is what keeps two legs off one database, so a collision is the
	// defect: every pair must map to its own key.
	pairs := [][2]string{{"unit", "db"}, {"integration", "db"}, {"unit", "cache"}, {"unit.db", "x"}, {"unit", "db.x"}}
	seen := map[string][2]string{}
	for _, p := range pairs {
		key := serviceInstanceKey(p[0], p[1])
		if prev, dup := seen[key]; dup {
			t.Fatalf("%v and %v share the key %q", prev, p, key)
		}
		seen[key] = p
	}
	if got := serviceInstanceKey("unit", "db"); got != "unit/db" {
		t.Fatalf("key = %q, want unit/db", got)
	}
}

func TestUnusableServiceIsANonRun(t *testing.T) {
	spec := serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432}
	rep, msg, _ := foldServiceProbe(spec, serviceProbe{
		BindErr: errors.New("start abc123 (aliased as db): service exited before healthcheck"),
	})

	if rep.Ready {
		t.Fatal("a service the engine never let a container bind to is reported ready")
	}
	if msg == "" {
		t.Fatal("an unusable service produced no errors[] entry, so nothing reaches combined-evidence.json")
	}
	if !strings.Contains(msg, "db") {
		t.Fatalf("the errors[] entry does not name the alias, so a four-service leg cannot say which one: %q", msg)
	}
	if rep.Error != msg {
		t.Fatalf("the row and the sentence disagree: %q vs %q", rep.Error, msg)
	}

	// The gate, at the threshold that suppresses everything suppressible.
	if gatedPassed(false, true, SeverityNone) {
		t.Fatal("a leg whose service never came up passed at --fail-on NONE")
	}
}

// A readiness check that was asked for and never succeeded is the error. The
// engine's port gate did pass — that is what makes falling back to it tempting,
// and what makes it a lie.
func TestReadyCmdTimeoutIsAnError(t *testing.T) {
	spec := serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432, ReadyCmd: "pg_isready -h db", ReadyTimeout: 30}
	rep, msg, _ := foldServiceProbe(spec, serviceProbe{
		ReadyRan:      true,
		ReadyStatus:   "2\n",
		ReadyAttempts: "15\n",
		ReadyWaited:   "30\n",
	})

	if rep.Ready {
		t.Fatal("a declared readiness check that never succeeded was reported ready")
	}
	if rep.ReadyVia == readyViaEngine {
		t.Fatal("the engine's port gate was substituted for the readiness check that was actually asked for")
	}
	if msg == "" {
		t.Fatal("a failed readiness check produced no errors[] entry")
	}
	if rep.WaitedSeconds == nil || *rep.WaitedSeconds != 30 || rep.ReadyAttempts == nil || *rep.ReadyAttempts != 15 {
		t.Fatalf("the loop counters were not carried: %+v", rep)
	}
}

// A readiness container that never produced a result is not a readiness check
// that failed a target, and it is certainly not one that passed.
func TestReadinessCheckThatCouldNotRunIsAnError(t *testing.T) {
	spec := serviceSpec{Alias: "cache", Image: "redis:7", Port: 6379, ReadyCmd: "redis-cli ping", ReadyTimeout: 30}
	rep, msg, _ := foldServiceProbe(spec, serviceProbe{ReadyReadErr: errors.New("exec: sh: not found")})

	if rep.Ready || msg == "" {
		t.Fatalf("a readiness check that could not run was not reported as a problem: ready=%v msg=%q", rep.Ready, msg)
	}
	if rep.ReadyVia == readyViaEngine {
		t.Fatal("the weaker engine claim was substituted for a check that never ran")
	}
}

// The differentiation fact. A single per-leg servicesReady boolean passes every
// other test in this file and fails this one.
func TestServiceReportsDifferPerAlias(t *testing.T) {
	good := serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432}
	bad := serviceSpec{Alias: "cache", Image: "redis:7", Port: 6379}

	okRep, okMsg, _ := foldServiceProbe(good, serviceProbe{})
	badRep, badMsg, _ := foldServiceProbe(bad, serviceProbe{BindErr: errors.New("service exited before healthcheck")})

	reports := []serviceReport{okRep, badRep}
	if len(reports) != 2 {
		t.Fatalf("two declared services produced %d rows", len(reports))
	}
	if reports[0].Ready == reports[1].Ready {
		t.Fatalf("one usable service and one dead one reported the same readiness: %+v", reports)
	}
	if reports[0].Alias != "db" || reports[1].Alias != "cache" {
		t.Fatalf("rows are not in declaration order: %+v", reports)
	}
	if okMsg != "" {
		t.Fatalf("a usable service produced an errors[] entry: %q", okMsg)
	}
	if strings.Contains(badMsg, "db") {
		t.Fatalf("the errors[] entry blames a service that was fine: %q", badMsg)
	}
}

// A service that came up on the port gate alone says so, because `ready: true`
// means two different things and a reader cannot be expected to guess which.
func TestEngineGateIsNamedAsTheWeakerClaim(t *testing.T) {
	rep, _, _ := foldServiceProbe(serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432}, serviceProbe{})
	if !rep.Ready || rep.ReadyVia != readyViaEngine {
		t.Fatalf("a service bound with no readyCmd is not recorded as ready via the engine gate: %+v", rep)
	}
	if rep.WaitedSeconds != nil || rep.ReadyAttempts != nil {
		t.Fatal("counters were fabricated for a readiness loop that never ran")
	}

	// And the envelope says it in words, not only in a field name.
	if w := servicesSummary("byo-test", []serviceReport{rep}); w == "" || !strings.Contains(w, "db") {
		t.Fatalf("no disclosure that this leg's claim is a floor: %q", w)
	}
}

// A leg whose services all passed a declared check has nothing to disclose.
// A line on every run is the noise that gets the line ignored when it counts.
func TestNoFloorDisclosureWhenEveryServicePassedItsOwnCheck(t *testing.T) {
	rep, _, _ := foldServiceProbe(
		serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432, ReadyCmd: "pg_isready", ReadyTimeout: 30},
		serviceProbe{ReadyRan: true, ReadyStatus: "0", ReadyAttempts: "3", ReadyWaited: "4"},
	)
	if !rep.Ready || rep.ReadyVia != readyViaCmd {
		t.Fatalf("a passing readiness check was not recorded as such: %+v", rep)
	}
	if w := servicesSummary("byo-test", []serviceReport{rep}); w != "" {
		t.Fatalf("a leg with nothing to disclose disclosed anyway: %q", w)
	}
}

// The assertion is on the serialised bytes, not on a struct field. The field
// that leaks is the one nobody thought to look at, and a struct-level check
// agrees with whatever the struct happens to be.
func TestServiceEnvValuesAreNotSerialised(t *testing.T) {
	const password = "hunter2-do-not-ship-me"
	spec := serviceSpec{
		Alias: "db", Image: "postgres:16", Port: 5432,
		Env: map[string]string{"POSTGRES_PASSWORD": password, "POSTGRES_DB": "app"},
	}
	rep, _, _ := foldServiceProbe(spec, serviceProbe{})

	raw, err := json.Marshal(newLegsReport(nil, nil, nil, []legReport{{
		Label: "dotnet", Image: "mcr.microsoft.com/dotnet/sdk:10.0", Ran: true, Services: []serviceReport{rep},
	}}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)

	if strings.Contains(body, password) {
		t.Fatalf("a declared env value reached the envelope:\n%s", body)
	}
	if strings.Contains(body, `"app"`) {
		t.Fatalf("a declared env value reached the envelope:\n%s", body)
	}
	for _, key := range []string{"POSTGRES_PASSWORD", "POSTGRES_DB"} {
		if !strings.Contains(body, key) {
			t.Fatalf("env key %q is absent, so the record cannot say what the service was configured with:\n%s", key, body)
		}
	}
}

// A leg that declares no services must produce the report it produced before
// services existed — byte for byte, and with no new line in the envelope.
func TestLegWithoutServicesIsUnchanged(t *testing.T) {
	leg := legReport{Label: "go", Image: "golang:1.26-alpine", Ran: true, CoverageMeasured: false}
	raw, err := json.Marshal(leg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "services") {
		t.Fatalf("a leg with no services carries a services key: %s", raw)
	}
	if w := servicesSummary("byo-test", nil); w != "" {
		t.Fatalf("a leg with no services produced a warning: %q", w)
	}
}

func TestValidateServicesRefusesMoreThanTheLimit(t *testing.T) {
	svcs := make([]serviceSpec, 0, serviceLimit+1)
	for i := 0; i <= serviceLimit; i++ {
		svcs = append(svcs, serviceSpec{Alias: fmt.Sprintf("svc%d", i), Image: "redis:7", Port: 6379})
	}
	err := validateServices("test-legs[0] (a)", svcs)
	if err == nil {
		t.Fatalf("%d services were accepted against a limit of %d — binding some of them and running the command is the failure this guards", len(svcs), serviceLimit)
	}
	if ok := validateServices("test-legs[0] (a)", svcs[:serviceLimit]); ok != nil {
		t.Fatalf("exactly the limit was refused: %v", ok)
	}
}

func TestValidateServicesRefusesAnUndeclaredPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		if err := validateServices("test-legs[0] (a)", []serviceSpec{{Alias: "db", Image: "postgres:16", Port: port}}); err == nil {
			t.Fatalf("port %d was accepted — a guessed port is a binding that looks configured", port)
		}
	}
}

func TestValidateServicesRefusesAnAliasThatIsNotAHostname(t *testing.T) {
	// Every one of these is a legal leg *label*. The alias is stricter because
	// it is resolved as a hostname and upper-cased into a variable name.
	for _, alias := range []string{"DB", "my_db", "my.db", "-db", "db-", "1db", ""} {
		if err := validateServices("test-legs[0] (a)", []serviceSpec{{Alias: alias, Image: "postgres:16", Port: 5432}}); err == nil {
			t.Fatalf("alias %q was accepted as a hostname", alias)
		}
	}
	for _, alias := range []string{"db", "db2", "my-db", "a"} {
		if err := validateServices("test-legs[0] (a)", []serviceSpec{{Alias: alias, Image: "postgres:16", Port: 5432}}); err != nil {
			t.Fatalf("alias %q is a valid hostname and was refused: %v", alias, err)
		}
	}
}

func TestValidateServicesRefusesADuplicateAlias(t *testing.T) {
	err := validateServices("test-legs[0] (a)", []serviceSpec{
		{Alias: "db", Image: "postgres:16", Port: 5432},
		{Alias: "db", Image: "redis:7", Port: 6379},
	})
	if err == nil {
		t.Fatal("one hostname was allowed to answer for two services")
	}
}

// readyTimeout without readyCmd is the budget for a check nobody declared.
// Ignoring it silently is how a consumer believes cicd is waiting when it is not.
func TestValidateServicesRefusesAReadyTimeoutWithNoCheck(t *testing.T) {
	if err := validateServices("test-legs[0] (a)", []serviceSpec{
		{Alias: "db", Image: "postgres:16", Port: 5432, ReadyTimeout: 30},
	}); err == nil {
		t.Fatal("readyTimeout was accepted with no readyCmd to spend it on")
	}
}

func TestReadyTimeoutDefaultsOnlyWhenACheckIsDeclared(t *testing.T) {
	svcs := []serviceSpec{{Alias: "db", Image: "postgres:16", Port: 5432, ReadyCmd: "pg_isready"}}
	if err := validateServices("test-legs[0] (a)", svcs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svcs[0].ReadyTimeout != defaultReadyTimeoutSeconds {
		t.Fatalf("readyTimeout = %d, want the default %d", svcs[0].ReadyTimeout, defaultReadyTimeoutSeconds)
	}
	if err := validateServices("test-legs[0] (a)", []serviceSpec{
		{Alias: "db", Image: "postgres:16", Port: 5432, ReadyCmd: "pg_isready", ReadyTimeout: maxReadyTimeoutSeconds + 1},
	}); err == nil {
		t.Fatal("an unbounded readiness budget was accepted")
	}
}

// The leg's command needs something deterministic to read. This is the mapping,
// pinned: a change here changes what every consumer's configuration must say.
func TestServiceEnvVarsNameTheAliasExactly(t *testing.T) {
	got := serviceEnvVars(serviceSpec{Alias: "my-db", Port: 5432})
	want := [][2]string{{"CICD_SERVICE_MY_DB_HOST", "my-db"}, {"CICD_SERVICE_MY_DB_PORT", "5432"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("serviceEnvVars = %v, want %v", got, want)
	}
}

// validServiceAlias makes this unreachable today. The check is what keeps it
// unreachable if the charset is ever widened, which is the change that would
// silently reintroduce it — so the guard is asserted directly.
func TestTwoAliasesCannotNameOneEnvironmentVariable(t *testing.T) {
	seen := map[string]string{}
	for _, alias := range []string{"db", "db2", "my-db", "a-b-c"} {
		prefix := serviceEnvPrefix(alias)
		if prev, clash := seen[prefix]; clash {
			t.Fatalf("aliases %q and %q both map to %s", prev, alias, prefix)
		}
		seen[prefix] = alias
	}
}

// Every one of these strings lands in a markdown table cell in the pull request
// comment, and nothing fences a bare sentence.
func TestServiceMessagesCarryNoBacktick(t *testing.T) {
	rep, msg, _ := foldServiceProbe(
		serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432},
		serviceProbe{BindErr: errors.New("start `whoami` (aliased as db): failed")},
	)
	for _, s := range []string{msg, rep.Error, servicesSummary("byo-test", []serviceReport{rep})} {
		if strings.Contains(s, "`") {
			t.Fatalf("a service message carries a backtick into the PR comment: %q", s)
		}
		if strings.ContainsAny(s, "\n\r") {
			t.Fatalf("a service message spans lines, which cuts a table row mid-cell: %q", s)
		}
	}
}

// The two counter files are disclosure, not verdict. When cicd could not read
// them back, the report must say so and stop measuring, rather than render a
// nil counter that reads like a probe that never counted — and the verdict,
// which comes from the status file alone, stands.
func TestUnreadableReadyCountersAreAWarningNotAVerdict(t *testing.T) {
	spec := serviceSpec{Alias: "db", Image: "postgres:16", Port: 5432, ReadyCmd: "pg_isready -h db", ReadyTimeout: 30}
	rep, msg, warn := foldServiceProbe(spec, serviceProbe{
		ReadyRan:         true,
		ReadyStatus:      "0\n",
		ReadyCountersErr: errors.New("read /tmp/ready.attempts: input/output error (token=hunter2)"),
	})

	if !rep.Ready || msg != "" {
		t.Fatalf("a readiness check that passed was reported as not passed over its counters: ready=%v err=%q", rep.Ready, msg)
	}
	if rep.ReadyAttempts != nil || rep.WaitedSeconds != nil {
		t.Fatalf("counters cicd could not read were reported as measured: %v %v", rep.ReadyAttempts, rep.WaitedSeconds)
	}
	for _, want := range []string{"db", "postgres:16", "could not be read back", "verdict stands", "input/output error"} {
		if !strings.Contains(warn, want) {
			t.Fatalf("warning lacks %q: %q", want, warn)
		}
	}
	if strings.Contains(warn, "hunter2") {
		t.Fatalf("the warning leaked a credential from the read error: %q", warn)
	}
}
