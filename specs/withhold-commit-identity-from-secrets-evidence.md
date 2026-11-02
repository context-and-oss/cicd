# Withhold commit identity from secrets evidence

## Why

`--redact` keeps the credential out of gitleaks' report. It does nothing about
the person who committed it. Measured on v8.30.1, every history (`detect`)
result carries the commit in `partialFingerprints`:

```
commitSha, email, author, date, commitMessage
```

The tree (`dir`) and shadow legs write the same five keys, all empty.

`mergeGitleaksSARIF` drops a history result whose rule, file and line the tree
leg already reported, so the identity reached the envelope exactly when it was
most sensitive: a secret deleted from the tree but still in history. The
envelope is a downloadable build artifact, is uploaded to GitHub code scanning,
and outlives the access of anyone who later leaves the repository. A secrets
scan that names who leaked the secret, in a document more widely readable than
the repository's own log, publishes something the consumer never asked it to.

## What changed

`withholdGitleaksCommitIdentity` (`src/security/gitleaksidentity.go`) rewrites
the report at the end of `gitleaksReadRun`, so every leg passes through it
before anything counts, merges or discloses.

- **An allowlist, not a denylist.** Only `commitSha` and `date` survive in
  `partialFingerprints`. A key a later gitleaks adds (`committerEmail`, say) is
  dropped until someone reviews it, rather than published until someone
  notices it.
- **Every leg.** The tree and shadow legs have nothing to withhold today; one
  rule for all three leaves no leg for a later gitleaks to start filling
  unnoticed.
- **A report it cannot walk is an error.** A `runs` that is not an array, a
  result or `partialFingerprints` that is not an object: the leg fails with a
  `gitleaks: …` error that never quotes the report. Passing it through would
  publish whatever it held.

## Trade-offs

- **`commitMessage` goes too.** It is free text: it can name people, and it can
  hold the very secret the scan found. The sha reaches it for anyone who needs
  it.
- **The message text is untouched.** gitleaks writes "… at commit <sha>", which
  is the sha already kept.
- **One-time code-scanning churn.** GitHub uses `partialFingerprints` to track
  an alert across runs. Consumers that upload the SARIF see existing history
  alerts close and reopen once on upgrade.

## Residue

- `commitSha` resolves to the author for anyone with read access to the
  repository. That is the repository's own access control, not cicd's.
- `date` stays, because the age of a leak decides whether rotation is urgent.

## Proof

- `src/security/gitleaksidentity_test.go`: the measured shape with a probe
  identity and a synthetic future key is stripped to sha and date, the finding
  count is unchanged, a report with nothing to withhold passes, and every
  shape it cannot walk is refused without quoting the probe.
- `scripts/smoke/gitleaks-identity.sh`: a real repository whose fictitious
  author commits a key assembled at run time and then deletes it. The smoke
  first asserts gitleaks reported the leaked commit's sha (the positive
  control), then that the name, email and subject appear nowhere in the
  envelope. With the filter disabled it fails.
