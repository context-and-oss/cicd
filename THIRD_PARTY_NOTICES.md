# Third-party notices and runtime dependencies

cicd is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE),
[NOTICE](NOTICE)). This file records the third-party material that is copied
into this tree, with the notices its licence requires, and the third-party
content cicd fetches at run time under terms of its own. It is a provenance
record kept by the maintainers, not legal advice or a legal review.

## Material copied into this tree

### Trivy licence categories

- **File:** [`src/security/testdata/trivy-0.70.0-license-categories.json`](src/security/testdata/trivy-0.70.0-license-categories.json)
- **Source:** [aquasecurity/trivy](https://github.com/aquasecurity/trivy) at
  tag `v0.70.0` — the `*Licenses` slices in
  `pkg/licensing/expression/category.go` and the `LicenseCategory` values in
  `pkg/fanal/types/license.go`.
- **What was copied:** the licence-category names and the licence identifiers
  listed under each, captured verbatim as data. cicd's tests compare this table
  with what the pinned Trivy image reports (`licensecategories_test.go`).
- **Licence:** Apache License, Version 2.0 (the same licence as cicd).
- **Upstream NOTICE** (Trivy `v0.70.0`), reproduced as Apache-2.0 §4(d)
  requires:

  ```text
  Trivy
  Copyright 2019-2020 Aqua Security Software Ltd.

  This product includes software developed by Aqua Security (https://aquasec.com).
  ```

When the Trivy pin moves and this file is regenerated, re-read the upstream
`NOTICE` at the new tag and update the text above.

### ZAP packaged-scan excerpts and option strings

- **Source:** [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) at tag
  `v2.17.0`:
  [`docker/zap_common.py`](https://github.com/zaproxy/zaproxy/blob/v2.17.0/docker/zap_common.py),
  [`docker/zap-api-scan.py`](https://github.com/zaproxy/zaproxy/blob/v2.17.0/docker/zap-api-scan.py),
  [`docker/zap-full-scan.py`](https://github.com/zaproxy/zaproxy/blob/v2.17.0/docker/zap-full-scan.py)
  and
  [`docker/zap-baseline.py`](https://github.com/zaproxy/zaproxy/blob/v2.17.0/docker/zap-baseline.py).
- **What is retained:** short excerpts and option strings in cicd's source
  and documentation explaining and handling packaged scans. These are
  shortened and integrated excerpts, not bundled copies of the complete
  upstream scripts.
- **Licence:** all four verified source headers specify Apache License,
  Version 2.0; see [LICENSE](LICENSE) for the licence and warranty disclaimer.
- **Applicable source notices:** `zap_common.py`, `zap-api-scan.py` and
  `zap-full-scan.py`: Copyright 2017 ZAP Development Team.
  `zap-baseline.py`: Copyright 2016 ZAP Development Team.
  These notices are also retained in [NOTICE](NOTICE).

This records the provenance and applicable source notices for the excerpts,
not an independent legal certification of the repository.

### Workflow compatibility adapter — rule body fetched at runtime

`src/security/semgrep_gha.py` is cicd's first-party adapter, not a bundled
upstream rule. The former embedded workflow-rule YAML is no longer distributed.
Inside the scan container the adapter reads the workflow rule from the pinned
`semgrep/semgrep-rules` checkout, retains its structural matching and metadata,
and replaces only its Bash metavariable matcher with cicd's compatibility regex.
The finding identifier and first-party explanation remain stable.

The generated rule remains under the upstream Semgrep Rules License v1.0,
**not** Apache-2.0. Its runtime copy prominently identifies the modifications
and retains the complete original source text, LICENSE and any root NOTICE as
comments, including notices a YAML parser would otherwise discard. Generation
or required-rule loading failure is a non-run, never a smaller clean scan.
The generated copy is not included in this repository or relicensed by cicd;
the runtime restrictions below still apply.

## Content fetched at run time, not distributed with cicd

### Default Semgrep rules — Semgrep Rules License v1.0, not Apache-2.0

`security.ScanSource` (and every composite and template that calls it) runs
Semgrep with `p/security-audit` by default. cicd does not fetch that pack from
the Semgrep registry: it clones
[semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) at commit
`16b9e6d45f10649f6a531ec4838ed9924372c3bc` (`semgrepRulesCommit` in
[`src/security/semgreppack.go`](src/security/semgreppack.go)) into the scan
container on every run. `p/owasp-top-ten` and `p/secrets`, when named, come
from the same commit. Any other registry pack you name is fetched live from the
Semgrep registry under the registry's terms.

That repository's `LICENSE` at that commit reads:

```text
Semgrep Rules License v1.0. For more details, visit https://semgrep.dev/legal/rules-license
```

The Semgrep Rules License is **not** an open-source licence and is separate
from the licence of the Semgrep engine (the `semgrep/semgrep` image). In
summary — read the [licence itself](https://semgrep.dev/legal/rules-license),
which governs — v1.0 permits use of the rules only for your own internal
business purposes, does not permit distributing them or making them available
to others as a service, and requires that applicable notices be retained.

What this means for you:

- cicd's Apache-2.0 licence covers cicd's code. It does not license the
  Semgrep rules, and cicd does not relicense them. The fetched packs are not
  bundled in this tree: [`src/security/rules/semgrep-*.txt`](src/security/rules/)
  list rule file paths and rule ids so cicd can check that every pinned rule
  loaded. The workflow compatibility adapter described above also obtains its
  upstream rule body only at runtime; its generated copy retains upstream terms.
- Running the default SAST scan over **your own** code in your own pipeline is
  the use the default was chosen for. Whether a particular use is "internal
  business purposes" is a question about your use and the licence, not about
  cicd.
- If you run cicd **as a hosted or managed service for others**, or
  **redistribute** an image, cache or bundle that contains the fetched rules,
  you need a suitable licence or permission from Semgrep for the rules, or you
  must supply rules whose licence allows that use.
- To supply your own rules, pass a configuration file checked into the scanned
  repository: `--sast-rulesets ./semgrep.yml` (or several, comma-separated) on
  `security scan-source` or on the `precommit` and `commit` composites, or the
  same value as the `sast-rulesets` input of the reusable GitHub workflows.
  A config path replaces the pinned packs entirely, so the scan reads no
  `semgrep-rules` content; SAST still runs and fails the gate if it could not.
  See [`src/security/CLAUDE.md`](src/security/CLAUDE.md#sast-scope--noise-control)
  for the config-path form. Choose rules whose licence fits your use; cicd does
  not ship an alternative default rule set.

### Tool images

Every scanner, linter and helper image cicd runs is pulled by digest from its
publisher's registry at run time and is not redistributed by this repository;
[docs/reference/runtime-images.md](docs/reference/runtime-images.md) lists them.
Each image is distributed under its publisher's own licence terms.

## Maintainer review of embedded diagrams

The maintainer reviewed and cleared the embedded raster images in
`docs/assets/environment/slots.drawio.png` and
`docs/assets/cd-model/canvas-compliance-ra.drawio.png` for inclusion.
This records the maintainer's approval, not an independently verified origin
or a claim of particular authorship or third-party licence. No additional
attribution or licence details were supplied.
