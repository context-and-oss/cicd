# AGENTS.md

Instructions for any coding agent working in this repository. The codebase
guide — layout, architecture rules, doctrine, commands — is
[CLAUDE.md](CLAUDE.md); read it too. This file holds the one rule that applies
before any of that.

## This is an open-source repository

Everything you write here is public: code, comments, tests, fixtures, specs,
capsules, docs, commit messages and pull request text. cicd is built and
measured against real consumer pipelines, and the measurement is welcome here.
The consumer is not. Nothing private reaches the tree, and there is no
deny-list to catch it afterwards — a list of the names to refuse would itself
publish them, and it could only ever refuse the names someone already thought
of. The rule is enforced by the author and by review ([REVIEW.md](REVIEW.md)),
so it is enforced by you.

Never write:

- **A consumer's or customer's name**, or the name of their product, repository,
  project, service, feed, host, URL, tenant or environment.
- **Anything lifted from a consumer's code**: file, class, route, profile or
  package names, error text, config values. Invent a neutral stand-in
  (`OrderController.cs`, `Staging`, `example-org`) that shows the same shape.
- **A private organisation's internals**: org or team names, org paths,
  ruleset names, internal tools, audit-log ids, internal URLs.
- **A person**: names, handles, emails. Say "a maintainer" or "a consumer".
- **References that only resolve inside a private repository**: issue and pull
  request numbers, commit SHAs, CI run ids, links to private repos or boards.
  The public tree carries no history, so they dangle — describe what the change
  did instead.
- **Figures precise enough to fingerprint a consumer**: an exact test count,
  package count or document size from a consumer run. Round it ("~400
  operations", "over 90% of the locked packages") — the argument survives, the
  fingerprint does not.
- **Third-party content without a licence that allows redistribution under
  Apache-2.0**: copied tables, catalogues, prose, icons and images. Link the
  source instead. In a `.drawio.png`, use draw.io's built-in shapes, never an
  image pulled from an icon site.
- **Secrets**, real or realistic-looking, outside a fixture that is marked
  `gitleaks:allow` and documented as fake.

When a spec or capsule needs to record what a consumer run showed, write it as
"a consumer", "a consumer monorepo" or "a .NET consumer", keep the mechanism and
the measured behaviour, and drop everything that would let a reader tell which
consumer it was. If you cannot tell whether something is internal, treat it as
internal and ask.
