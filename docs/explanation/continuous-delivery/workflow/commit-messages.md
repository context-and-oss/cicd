# Commit Messages

> **Semantic commit messages for traceability**

Conventional commits provide structured messages that enable automated changelog generation and maintain clear project history.

---

## Why Conventional Commits?

Semantic commit messages enable:

- **Automated changelog generation** - Tools can extract features, fixes, and breaking changes
- **Clear project history** - Anyone can understand what changed and why
- **Semantic versioning** - Commit types inform version bumps (feat = minor, fix = patch)
- **Traceability** - Link commits to issues and requirements

---

## Basic Format

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Key Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

---

## A subject that does not parse releases nothing — silently

Worth knowing before you rely on commit messages to drive versioning: when the
convention is what selects the version, breaking the convention does not produce an
error. It produces *no release*, and no release is reported exactly the way a
deliberate `chore:` sweep is reported — the version generator prints the version
that is already tagged and exits successfully.

Measured with git-cliff 2.13.1 on this repository's configuration, one commit after
a tag:

| subject | resulting version |
|---|---|
| `fix(quality): a real fix` | patch bump |
| `chore: housekeeping` | unchanged, "nothing to bump" |
| `Second-pass review follow-up on the gate.` | **unchanged**, one WARN line in the log |

The last row is a real commit on this repository's `main`. The fix shipped to
nobody, CD reported success, and the drift detector could not see it either — it
asks the same generator the same question and gets the same silence.

The remedy is to check the subject, not the resulting version, because the version
is where the information was lost. `ci.yml`'s `commit-subjects` job does that on
every pull request; see
[refuse-a-commit-git-cliff-cannot-release](../../../../specs/refuse-a-commit-git-cliff-cannot-release.md).

---

## Related Documentation

- [Traceability Requirements](../cd-model/stages.md#stage-4-commit) - Stage 4 traceability
- [Pre-commit Setup](../quality-gates/precommit-setup.md) - Pre-commit hooks
- [Trunk-Based Development](./trunk-based-development.md) - Development workflow
- [Branching Strategies](./branching-strategies.md) - Branch naming
