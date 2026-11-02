//go:build !unit_test

package main

import (
	"context"
	"dagger/evidence/internal/dagger"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Evidence is the Dagger module that aggregates the per-module evidence
// envelopes of one pipeline run into a combined audit directory (Wrap), with
// the findings table ordered and truncated by a rule the envelope states, and
// records a stage that could not produce its own envelope (Failure).
type Evidence struct{}

// Wrap aggregates one or more evidence envelope files into a single audit directory.
//
// The returned directory contains:
//   - combined-evidence.json  — merged envelope across all inputs
//   - findings.sarif          — concatenated SARIF runs from all scanning modules
//   - sbom.cdx.json           — merged CycloneDX document from sbom/vuln-scan modules
//   - parts/NN-<module>.json  — each input envelope, byte-for-byte as produced
//   - parts/index.json        — what parts/ should contain, and what each part said
//   - concerns/<concern>.json — the run re-indexed by question (sast, sca, …),
//     as pointers into parts/ rather than copies
//   - concerns/index.json     — every concern answered, and every one that was
//     not — the denominator that stops a missing section reading as a clean one
//
// The bundle is written to the module runtime's scratch workdir and returned by
// reference (dag.CurrentModule().Workdir), NOT built with dag.Directory().
// WithNewFile. That is not a style preference. WithNewFile encodes the file's
// entire contents inside the returned Directory's ID, and a module function's
// return value is serialised through a 128 MiB output file — so building the
// bundle in the DAG makes the bundle's own size the limit on whether the
// function can return anything at all. It did: a consumer's run assembled
// just over 128 MiB of evidence and got
//
//	read function output file: file size 134250496 exceeds limit 134217728
//
// instead of a verdict, an artifact, or any indication of what had been found.
// The diagnostic size is the public 128 MiB limit plus one fixed 32 KiB read
// chunk, not the payload's measured size.
// Written to the workdir, the content travels through the engine's filesystem
// and the returned ID stays a small reference regardless of how much evidence
// the run produced.
func (m *Evidence) Wrap(
	ctx context.Context,
	// Evidence files returned by individual modules.
	envelopes []*dagger.File,
	// Git commit SHA for the overall pipeline run.
	commitSha string,
	// Git branch name.
	branch string,
	// Repository URL.
	repoUrl string,
	// Optional application identity. Both fields must be supplied together.
	// +optional
	appId string,
	// Caller-declared source scope, relative to the original checkout.
	// +optional
	sourcePaths []string,
	// Defer application dependency assessment and do not emit an empty SBOM.
	// Records explicit SKIPPED evidence; repository mode keeps its normal SBOM.
	// +optional
	omitSbom bool,
) (*dagger.Directory, error) {
	start := time.Now()
	if (appId == "") != (len(sourcePaths) == 0) {
		return nil, fmt.Errorf("app-id and source-paths must be supplied together")
	}
	repo := repoContext{RepoURL: repoUrl, CommitSHA: commitSha, Branch: branch, AppID: appId, SourcePaths: sourcePaths}

	var envs []*envelope
	// The bytes each envelope arrived as, kept alongside the parsed value so
	// parts/ can ship what the module actually wrote rather than this module's
	// re-marshalling of the subset of it that schema.go happens to model.
	var raws []string
	for i, f := range envelopes {
		contents, err := f.Contents(ctx)
		if err != nil {
			// The same 128 MiB ceiling applies on the way IN, and the engine
			// reports it as a bare byte count that is always the limit plus one
			// read chunk — it names neither the file nor what to do. Measured:
			// a 145 MiB envelope fails here with exactly the 134250496 that a
			// too-large *return* value produces, so without this the two
			// failures are indistinguishable in a log.
			return nil, fmt.Errorf("reading envelope %d: %w "+
				"(a single module's evidence.json cannot exceed Dagger's 128 MiB "+
				"transfer limit — the producing module must bound the payload it "+
				"embeds, not this aggregator)", i, err)
		}

		if appId != "" {
			contents, err = stampApp(contents, repo)
			if err != nil {
				return nil, fmt.Errorf("envelope %d: %w", i, err)
			}
		}
		var single envelope
		if err := json.Unmarshal([]byte(contents), &single); err == nil && single.ModuleName != "" {
			envs = append(envs, &single)
			raws = append(raws, contents)
			continue
		}

		return nil, fmt.Errorf("envelope %d: unrecognised format", i)
	}

	if omitSbom {
		deferred, err := deferredAppDependencies(envs, repo, start)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(deferred)
		if err != nil {
			return nil, err
		}
		envs = append(envs, deferred)
		raws = append(raws, string(data))
	}
	combined := buildCombined(moduleName, moduleStage, repo, envs, start)
	if appId != "" {
		combined.Warnings = append(combined.Warnings, "Application scope is caller-declared; complete command scope is not inferred.")
	}

	// Bound the detail list before marshalling, and record the truncation in the
	// same document it applies to — a reader must not have to know this cap
	// exists to know whether they are looking at all of it.
	var truncated string
	combined.Findings, truncated = capFindings(combined.Findings)
	if truncated != "" {
		combined.Warnings = append(combined.Warnings, truncated)
	}

	sarifDoc := mergeSARIF(envs)
	if appId != "" {
		var err error
		sarifDoc, err = appSARIF(sarifDoc, appId)
		if err != nil {
			return nil, fmt.Errorf("application SARIF identity: %w", err)
		}
	}
	var cdxJSON []byte
	if !omitSbom {
		cdxDoc, err := mergeCycloneDX(envs, repo, start)
		if err != nil {
			return nil, fmt.Errorf("merge cyclonedx: %w", err)
		}
		cdxJSON, err = marshalBundleDoc("sbom.cdx.json", cdxDoc)
		if err != nil {
			return nil, err
		}
	}

	combinedJSON, err := marshalBundleDoc("combined-evidence.json", combined)
	if err != nil {
		return nil, err
	}
	sarifJSON, err := marshalBundleDoc("findings.sarif", sarifDoc)
	if err != nil {
		return nil, err
	}

	// Start from nothing. The scratch workdir is not guaranteed to be untouched,
	// and a leftover part file from an earlier call is precisely a stale signal
	// read as this run's evidence.
	if err := os.RemoveAll(auditDirName); err != nil {
		return nil, fmt.Errorf("clear audit dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(auditDirName, partsDirName), 0o755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(auditDirName, concernsDirName), 0o755); err != nil {
		return nil, fmt.Errorf("create concerns dir: %w", err)
	}

	for _, f := range []struct {
		name string
		data []byte
	}{
		{"combined-evidence.json", combinedJSON},
		{"findings.sarif", sarifJSON},
	} {
		if err := writeBundleFile(f.name, f.data); err != nil {
			return nil, err
		}
	}
	if !omitSbom {
		if err := writeBundleFile("sbom.cdx.json", cdxJSON); err != nil {
			return nil, err
		}
	}

	// One file per part of the run, plus the index that says how many parts
	// there should be. The merged documents answer "what did the pipeline
	// find"; these answer "what did each module do", which no merge can
	// reconstruct once the rows are pooled.
	names := make([]string, len(envs))
	sizes := make([]int, len(envs))
	for i, e := range envs {
		names[i] = partFileName(i, e)
		sizes[i] = len(raws[i])
		if err := writeBundleFile(filepath.Join(partsDirName, names[i]), []byte(raws[i])); err != nil {
			return nil, err
		}
	}
	indexJSON, err := marshalBundleDoc(filepath.Join(partsDirName, "index.json"), buildPartsIndex(envs, names, sizes))
	if err != nil {
		return nil, err
	}
	if err := writeBundleFile(filepath.Join(partsDirName, "index.json"), indexJSON); err != nil {
		return nil, err
	}

	// The same run, indexed by the question instead of by the producer. Written
	// after parts/ because every row in it points at a file parts/ just wrote:
	// an index naming a file that does not exist is worse than no index.
	concernFiles, concernIdx := buildConcerns(envs, names)
	for _, entry := range concernIdx.Concerns {
		name := filepath.Join(concernsDirName, filepath.Base(entry.File))
		data, err := marshalBundleDoc(name, concernFiles[filepath.Base(entry.File)])
		if err != nil {
			return nil, err
		}
		if err := writeBundleFile(name, data); err != nil {
			return nil, err
		}
	}
	concernIndexJSON, err := marshalBundleDoc(filepath.Join(concernsDirName, "index.json"), concernIdx)
	if err != nil {
		return nil, err
	}
	if err := writeBundleFile(filepath.Join(concernsDirName, "index.json"), concernIndexJSON); err != nil {
		return nil, err
	}

	// Drop the raw stdout+stderr of any failed step that captured it into the
	// audit dir, so a failing test/scan is debuggable from the uploaded artifact
	// alone — combined-evidence.json records only *that* a step failed and its
	// one-line error, not the failing test's output. Only failed envelopes are
	// materialised, keeping green runs' artifacts lean.
	usedNames := map[string]bool{}
	for _, e := range envs {
		if e.Passed || strings.TrimSpace(e.RawOutputRef) == "" {
			continue
		}
		if err := writeBundleFile(rawOutputFileName(e, usedNames), []byte(e.RawOutputRef)); err != nil {
			return nil, err
		}
	}

	return dag.CurrentModule().Workdir(auditDirName), nil
}

// writeBundleFile writes one file at a path relative to the audit directory
// being assembled in the module runtime's scratch workdir.
func writeBundleFile(name string, data []byte) error {
	if err := os.WriteFile(filepath.Join(auditDirName, name), data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}
