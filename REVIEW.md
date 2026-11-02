# REVIEW.md

What a reviewer checks on every pull request, before correctness. The
correctness doctrine lives in [CLAUDE.md](CLAUDE.md) and
[docs/explanation/doctrine.md](docs/explanation/doctrine.md); this file is the
part that has no test.

## Nothing private reaches a public tree

This repository is open source, and no automated check guards what it must not
contain: a deny-list would publish the names it refuses, and could only refuse
the ones already known. The author is held to [AGENTS.md](AGENTS.md); review is
the second and last line. Read the whole diff — code, comments, test data,
fixtures, specs, capsules, docs — plus the commit messages and the pull request
description, and request changes for any of:

- A consumer's, customer's or private organisation's name, or the name of
  their product, repository, feed, host, URL, ruleset, team or environment.
- Identifiers carried over from a consumer's code (file, class, route, profile
  or package names) where a neutral stand-in would show the same thing.
- A person's name, handle or email.
- An issue or pull request number, commit SHA, CI run id or link that only
  resolves inside a private repository.
- An exact figure from a consumer run that would let a reader identify the
  consumer, where a rounded one makes the same argument.
- Copied third-party material — text, tables, data files, icons, images —
  without a licence compatible with Apache-2.0. A `.drawio.png` embeds its
  draw.io source, so check that source for image URLs too, not only the
  rendered picture.
- Anything that looks like a credential, unless it is a documented fake in a
  fixture marked `gitleaks:allow`.

A finding here blocks the merge whatever else the change gets right: once it is
public, removing it from the tree does not remove it from every clone, fork and
cache that already has it.
