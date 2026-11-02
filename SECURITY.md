# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem in cicd itself.
Use GitHub's private vulnerability reporting instead: **Security → Report a
vulnerability** on this repository. That opens a private advisory only the
maintainers can read, and it is where we will reply.

Include what you can of:

- the module or workflow affected (`src/security`, `templates/azure-devops/commit.yml`, …)
- the version pin you ran it with (`@vX.Y.Z`)
- how to reproduce it, and what a consumer would observe

We aim to acknowledge a report promptly and to keep the reporter informed while
it is triaged and fixed. A fix ships as a normal release; the advisory is
published once a fixed version is tagged.

## What counts

In scope is anything that makes cicd report something other than what it
measured, or that exposes a consumer's secret or source. The founding doctrine
in [docs/explanation/doctrine.md](docs/explanation/doctrine.md) applies: a tool that could not run reading as "clean"
is a security bug, not a usability bug. Examples:

- a scanner non-run that produces `passed=true`
- a credential reaching an evidence envelope, a log, or a PR comment
- a pinned image or module reference that resolves to something other than
  what the pin names

Findings in the third-party tools cicd runs (Semgrep, Trivy, gitleaks, ZAP,
conftest, …) belong with those projects; a report here is welcome when cicd's
use of the tool is what makes the finding reachable.

## Security model

What cicd trusts, and what it does not, so a report can say which line it
crosses.

**The repository under test is trusted code.** cicd runs the consumer's own
commands (`--test-cmd`, `--build-cmd`, `--prepare-cmd`, the app commands, and
the package managers' install scripts they trigger) as programs, not as data.
They run inside Dagger containers on the consumer's runner, with the source tree
mounted. Anything those commands can do, a commit to the repository can do.

**Feed tokens reach the containers that install packages, and nothing else.**
`NPM_FEED_TOKEN` and `NUGET_FEED_TOKEN` are mounted as Dagger secrets into the
prepare, lint, test and build containers that restore from the private feed,
because the restore cannot authenticate otherwise. A command in those containers
can read them. Scope the tokens to read-only package access. The notification
credentials (`TEAMS_WEBHOOK`, the GitHub and Azure DevOps tokens) reach only the
notify step and the PR-comment step, never a container that runs consumer code.

**Untrusted contributors get no secrets.** The GitHub templates trigger on
`push`, `pull_request`, `schedule` and `workflow_dispatch`, never
`pull_request_target`, so a pull request from
a fork runs without the repository's secrets and with a read-only
`GITHUB_TOKEN`. Keep it that way: switching a template to `pull_request_target`
runs a stranger's commands with your feed tokens.

**Values reach a shell as arguments, never as source.** No workflow value is
spliced into a `run:` body (`check_run_expressions`), no Azure DevOps macro into
a bash body (`check_value_interpolation`), and no consumer command into cicd's
own shell script (it runs as `sh -c "$1"`). A branch name carrying `$(` is a
string, not a command.

**Secrets stay out of what cicd writes.** gitleaks always runs with `--redact`,
notify scrubs credential values and URL paths from every error it returns, and
no evidence envelope, log line or PR comment carries a token. A credential
appearing in any of them is in scope above.

**The AI risk scan sends source to the model you choose.** `risk scan` is a
local, opt-in command, not part of any composite. It sends file contents to
Anthropic (the Claude CLI or `dag.LLM()`) or to the `--llm-url` endpoint. Git
decides which files exist; credential-file classes and Git metadata are withheld
whether tracked or not, a worktree whose metadata is not mounted is refused, and
`scan-manifest.json` lists every path sent. A secret written into an ordinary
source file is sent — the path policy is not a secrets scanner. See
[the risk module README](src/risk/README.md#what-the-scan-sends-to-the-model).

**Loopback is not a trust boundary.** `claude-proxy.js` binds to `127.0.0.1`,
which every local OS user and every page in a local browser can reach, so it
requires a bearer token from its environment and refuses foreign `Host`, any
`Origin`, non-JSON bodies and malformed messages before it starts the Claude
CLI, which it runs with tools and session persistence off. A request that
reaches the CLI without the token is in scope above.

**The Dagger engine runs privileged on the runner.** That is Dagger's model,
not cicd's. The runner is the isolation boundary; use an ephemeral runner for
anything you would not run on a shared one.

## Supported versions

Only the latest tagged release receives fixes. Consumers pin `@vX.Y.Z` and are
expected to move forward; Renovate configuration for that is in
[`default.json`](default.json).
