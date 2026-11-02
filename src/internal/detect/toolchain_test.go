package detect_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/context-and-oss/cicd/internal/detect"
)

func TestToolchain_Precedence(t *testing.T) {
	cases := []struct {
		name     string
		lang     string
		explicit string
		files    fstest.MapFS
		want     string
	}{
		{
			name:     "explicit param wins over present .nvmrc",
			lang:     "node",
			explicit: "registry.internal/node:22@sha256:abc",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("18")}},
			want:     "registry.internal/node:22@sha256:abc",
		},
		{
			name:     "explicit param wins over present global.json",
			lang:     "dotnet",
			explicit: "mcr.microsoft.com/dotnet/sdk:9.0",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"sdk":{"version":"8.0.100"}}`)}},
			want:     "mcr.microsoft.com/dotnet/sdk:9.0",
		},
		{
			name:  "detected version beats pinned default",
			lang:  "node",
			files: fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("22")}},
			want:  "node:22-alpine",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detect.ResolveToolchain(tc.lang, tc.explicit, tc.files)
			if got != tc.want {
				t.Errorf("ResolveToolchain(%q, %q) = %q, want %q", tc.lang, tc.explicit, got, tc.want)
			}
		})
	}
}

func TestToolchain_Nvmrc(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"partial major version", "22", "node:22-alpine"},
		{"full version with leading v", "v22.4.1", "node:22-alpine"},
		{"surrounding whitespace", "  20.11.0\n", "node:20-alpine"},
		{"lts alias falls through", "lts/iron", "node:22-alpine"},
		{"junk falls through", "not a version", "node:22-alpine"},
		{"empty file falls through", "", "node:22-alpine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte(tc.content)}}
			got := detect.ResolveToolchain("node", "", fsys)
			if got != tc.want {
				t.Errorf(".nvmrc %q resolved to %q, want %q", tc.content, got, tc.want)
			}
		})
	}
}

func TestToolchain_GlobalJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"sdk version maps to major.minor", `{"sdk":{"version":"8.0.100"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"newer sdk version", `{"sdk":{"version":"9.0.203"}}`, "mcr.microsoft.com/dotnet/sdk:9.0"},
		{"malformed JSON falls through", `{"sdk":`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"missing sdk key falls through", `{"tools":{"dotnet":"8.0.100"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"non-numeric version falls through", `{"sdk":{"version":"latest"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
		{"major-only version falls through", `{"sdk":{"version":"8"}}`, "mcr.microsoft.com/dotnet/sdk:8.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(tc.content)}}
			got := detect.ResolveToolchain("dotnet", "", fsys)
			if got != tc.want {
				t.Errorf("global.json %q resolved to %q, want %q", tc.content, got, tc.want)
			}
		})
	}
}

func TestToolchain_Defaults(t *testing.T) {
	cases := []struct {
		lang string
		want string
	}{
		{"go", "golang:1.26-alpine"},
		{"node", "node:22-alpine"},
		{"python", "python:3.12-slim"},
		{"dotnet", "mcr.microsoft.com/dotnet/sdk:8.0"},
	}
	empty := fstest.MapFS{"README.md": &fstest.MapFile{}}
	for _, tc := range cases {
		t.Run(tc.lang, func(t *testing.T) {
			got := detect.ResolveToolchain(tc.lang, "", empty)
			if got != tc.want {
				t.Errorf("default for %s = %q, want %q", tc.lang, got, tc.want)
			}
		})
	}
}

func TestToolchain_NoVersionFileConventionForGoPython(t *testing.T) {
	// go and python have no version-file convention wired — a stray .nvmrc or
	// global.json must not leak into their resolution.
	fsys := fstest.MapFS{
		".nvmrc":      &fstest.MapFile{Data: []byte("22")},
		"global.json": &fstest.MapFile{Data: []byte(`{"sdk":{"version":"9.0.100"}}`)},
	}
	if got := detect.ResolveToolchain("go", "", fsys); got != "golang:1.26-alpine" {
		t.Errorf("go resolved to %q, want pinned default", got)
	}
	if got := detect.ResolveToolchain("python", "", fsys); got != "python:3.12-slim" {
		t.Errorf("python resolved to %q, want pinned default", got)
	}
}

// TestToolchainDetail_Provenance is the matrix that used to be unrepresentable.
// Every row asserts the image, which level chose it, and — the point of the
// change — whether a note was produced.
//
// The rows to read first are the pairs that resolve to the *same image* and
// differ only in Note: no global.json and a runner-only global.json both land
// on the pinned 8.0 band, and before this they were indistinguishable in every
// output cicd produced.
func TestToolchainDetail_Provenance(t *testing.T) {
	cases := []struct {
		name     string
		lang     string
		explicit string
		files    fstest.MapFS
		want     string
		wantFrom string
		wantNote bool
	}{
		{
			name:     "explicit image reports itself as explicit and notes nothing",
			lang:     "dotnet",
			explicit: "registry.internal/sdk@sha256:abc",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"test":{"runner":"Microsoft.Testing.Platform"}}`)}},
			want:     "registry.internal/sdk@sha256:abc",
			wantFrom: detect.ToolchainFromExplicit,
			// An explicit image is not a fall-through. cicd never consulted the
			// file, so there is nothing to disclose about having ignored it.
			wantNote: false,
		},
		{
			name:     "usable sdk.version reports global-json and notes nothing",
			lang:     "dotnet",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"sdk":{"version":"10.0.100"}}`)}},
			want:     "mcr.microsoft.com/dotnet/sdk:10.0",
			wantFrom: detect.ToolchainFromGlobalJSON,
			wantNote: false,
		},
		{
			name:     "no global.json at all is silent",
			lang:     "dotnet",
			files:    fstest.MapFS{},
			want:     "mcr.microsoft.com/dotnet/sdk:8.0",
			wantFrom: detect.ToolchainFromDefault,
			// The negative control for the whole change. Silence here has to keep
			// meaning "this tree pins no version"; a note on every .NET run would
			// destroy the only thing that makes the note above informative.
			wantNote: false,
		},
		{
			name:     "runner-only global.json lands on the default band and says so",
			lang:     "dotnet",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"test":{"runner":"Microsoft.Testing.Platform"}}`)}},
			want:     "mcr.microsoft.com/dotnet/sdk:8.0",
			wantFrom: detect.ToolchainFromDefault,
			// The measured case behind this rule, and the row a "declared but
			// unparseable" trigger would have left silent: sdk.version is absent
			// here, not malformed. The 8.0 band predates the runner opt-in this
			// very file is asking for.
			wantNote: true,
		},
		{
			name:     "bare major sdk.version is present-but-unusable",
			lang:     "dotnet",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"sdk":{"version":"10"}}`)}},
			want:     "mcr.microsoft.com/dotnet/sdk:8.0",
			wantFrom: detect.ToolchainFromDefault,
			wantNote: true,
		},
		{
			name:     "malformed global.json is present-but-unusable",
			lang:     "dotnet",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"sdk":`)}},
			want:     "mcr.microsoft.com/dotnet/sdk:8.0",
			wantFrom: detect.ToolchainFromDefault,
			wantNote: true,
		},
		{
			name:     "usable .nvmrc reports nvmrc and notes nothing",
			lang:     "node",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("22")}},
			want:     "node:22-alpine",
			wantFrom: detect.ToolchainFromNvmrc,
			wantNote: false,
		},
		{
			name:     "no .nvmrc at all is silent",
			lang:     "node",
			files:    fstest.MapFS{},
			want:     "node:22-alpine",
			wantFrom: detect.ToolchainFromDefault,
			wantNote: false,
		},
		{
			name:     "nvm alias lands on the default band and says so",
			lang:     "node",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("lts/iron")}},
			want:     "node:22-alpine",
			wantFrom: detect.ToolchainFromDefault,
			// lts/iron is idiomatic nvm and not a mistake, which is exactly why
			// the disclosure matters: the consumer did the reasonable thing and
			// is on the default band regardless of which release "iron" names.
			wantNote: true,
		},
		{
			name:     "empty .nvmrc lands on the default band and says so",
			lang:     "node",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("   \n")}},
			want:     "node:22-alpine",
			wantFrom: detect.ToolchainFromDefault,
			wantNote: true,
		},
		{
			name:     "a language with no version-file convention is silent",
			lang:     "go",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("lts/iron")}},
			want:     "golang:1.26-alpine",
			wantFrom: detect.ToolchainFromDefault,
			// A .nvmrc is not a file the go leg was ever going to read, so it is
			// not a file the go leg ignored. Noting it would accuse the consumer
			// of a mistake they did not make.
			wantNote: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detect.ResolveToolchainDetail(tc.lang, tc.explicit, tc.files)
			if got.Image != tc.want {
				t.Errorf("Image = %q, want %q", got.Image, tc.want)
			}
			if got.From != tc.wantFrom {
				t.Errorf("From = %q, want %q", got.From, tc.wantFrom)
			}
			if (got.Note != "") != tc.wantNote {
				t.Errorf("Note presence = %v (%q), want %v", got.Note != "", got.Note, tc.wantNote)
			}
			// The whole change must be image-preserving: ResolveToolchain is
			// now a wrapper, and every caller that still uses it has to keep
			// getting the byte-identical answer it got before.
			if bare := detect.ResolveToolchain(tc.lang, tc.explicit, tc.files); bare != got.Image {
				t.Errorf("ResolveToolchain = %q but ResolveToolchainDetail.Image = %q — the wrapper changed behaviour", bare, got.Image)
			}
		})
	}
}

// TestToolchainDetail_NoteNamesTheFileAndTheImage keeps the note actionable.
// A disclosure that does not say which file or which image was used instead
// sends the reader looking, which is most of the way back to saying nothing.
func TestToolchainDetail_NoteNamesTheFileAndTheImage(t *testing.T) {
	cases := []struct {
		name     string
		lang     string
		files    fstest.MapFS
		wantFile string
	}{
		{
			name:     "global.json",
			lang:     "dotnet",
			files:    fstest.MapFS{"global.json": &fstest.MapFile{Data: []byte(`{"test":{"runner":"Microsoft.Testing.Platform"}}`)}},
			wantFile: "global.json",
		},
		{
			name:     "nvmrc",
			lang:     "node",
			files:    fstest.MapFS{".nvmrc": &fstest.MapFile{Data: []byte("lts/jod")}},
			wantFile: ".nvmrc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detect.ResolveToolchainDetail(tc.lang, "", tc.files)
			if got.Note == "" {
				t.Fatal("expected a note")
			}
			if !strings.Contains(got.Note, tc.wantFile) {
				t.Errorf("note does not name the file %q: %s", tc.wantFile, got.Note)
			}
			if !strings.Contains(got.Note, got.Image) {
				t.Errorf("note does not name the image used instead (%q): %s", got.Image, got.Note)
			}
			// One line. notify renders each warning as a markdown list item, so
			// a newline here would split one disclosure into two bullets, the
			// second of which reads as a separate finding.
			if strings.ContainsAny(got.Note, "\n\r") {
				t.Errorf("note must be a single line: %q", got.Note)
			}
		})
	}
}

// TestToolchainDetail_NoteBoundsHostileContent covers the adversarial shape of
// a version file: it is arbitrary bytes from the repository being graded, and
// it ends up in an evidence envelope and a pull-request comment.
func TestToolchainDetail_NoteBoundsHostileContent(t *testing.T) {
	t.Run("oversized value is truncated and says so", func(t *testing.T) {
		huge := strings.Repeat("A", 4096)
		got := detect.ResolveToolchainDetail("node", "", fstest.MapFS{
			".nvmrc": &fstest.MapFile{Data: []byte(huge)},
		})
		if got.Note == "" {
			t.Fatal("expected a note")
		}
		if len(got.Note) > 400 {
			t.Errorf("note is unbounded (%d bytes): %q", len(got.Note), got.Note)
		}
		// Marked, not silent. A quietly shortened value is a value the reader
		// believes they are seeing in full.
		if !strings.Contains(got.Note, "truncated from 4096 bytes") {
			t.Errorf("truncation is not disclosed: %q", got.Note)
		}
	})

	t.Run("backticks and newlines cannot reach the renderer", func(t *testing.T) {
		got := detect.ResolveToolchainDetail("node", "", fstest.MapFS{
			".nvmrc": &fstest.MapFile{Data: []byte("x`y\nz")},
		})
		if got.Note == "" {
			t.Fatal("expected a note")
		}
		if strings.Contains(got.Note, "\n") {
			t.Errorf("note contains a newline: %q", got.Note)
		}
		// And a backtick deliberately DOES survive, which is the boundary this
		// case exists to record rather than an omission. Go's %q escapes quotes
		// and control characters and leaves a backtick raw, and that is
		// correct: markdown safety belongs to notify's codeSpan, which fences
		// with the longest internal run plus one, so the span cannot be closed
		// from inside. Replacing the byte here would re-introduce the stripping
		// that CAPS-027 rejected — a .nvmrc's content is what the consumer
		// reads back, and editing it is the quiet mutation that spec refused —
		// and would leave two copies of one rule free to disagree.
		if !strings.Contains(got.Note, "`") {
			t.Errorf("expected the backtick to be carried verbatim, got %q", got.Note)
		}
	})

	t.Run("control characters are dropped", func(t *testing.T) {
		got := detect.ResolveToolchainDetail("node", "", fstest.MapFS{
			".nvmrc": &fstest.MapFile{Data: []byte("a\x00\x07b")},
		})
		if strings.ContainsAny(got.Note, "\x00\x07") {
			t.Errorf("note carries control characters: %q", got.Note)
		}
	})
}
