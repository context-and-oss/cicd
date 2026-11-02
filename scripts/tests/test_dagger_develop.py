"""Regression proof for scripts/ci/dagger-develop.sh and its classifier.

A top-level generated-code error can hide a transport failure while fetching
modules. Retrying that fault can help; retrying an undefined symbol cannot.

The fixtures below are synthetic diagnostic examples. Revisions, timestamps,
TUI counters, durations and the timeout address are invented, while the public
tool error shapes and multiline output are retained:

* SUMDB_STREAM_RESET — a checksum-database HTTP/2 reset below the codegen error.
* UNDEFINED_SYMBOL — an untagged dagger.gen.go referencing entrypoints that
  the -tags unit_test build excludes.

The property that matters is in the middle test: neither classification can
produce a green. The classifier chooses the message and the retry budget, never
the verdict.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLASSIFIER = REPO_ROOT / "scripts" / "ci" / "classify-dagger-develop-failure.sh"
WRAPPER = REPO_ROOT / "scripts" / "ci" / "dagger-develop.sh"

SUMDB_STREAM_RESET = """\
34  : ┆ ┆ ┆ [2m14s] | go: dagger.io/dagger@0123456789abcdef0123456789abcdef01234567: \
dagger.io/dagger@v0.20.6-0.20400210083000-0123456789ab: verifying module: \
dagger.io/dagger@v0.20.6-0.20400210083000-0123456789ab: reading \
https://sum.golang.org/tile/8/0/x205/155: stream error: stream ID 31; \
INTERNAL_ERROR; received from peer
34  : ┆ ┆ ┆ [2m14s] | 2040/02/10 08:34:16 ERROR post-command failed error="exit status 1"
12  : ┆ develop . ERROR [2m21s]
12  : ┆ ! failed to apply generated code: exit code: 1
Error: failed to apply generated code: exit code: 1
"""

UNDEFINED_SYMBOL = """\
go: downloading dagger.io/dagger v0.20.6
./dagger.gen.go:64:10: undefined: Security
./dagger.gen.go:71:10: undefined: Security
./dagger.gen.go:88:3: undefined: Security
Error: failed to apply generated code: exit code: 1
"""

PROXY_503 = """\
go: dagger.io/dagger@v0.20.6: module lookup disabled by GOPROXY=off
go: downloading dagger.io/dagger v0.20.6: reading \
https://proxy.golang.org/dagger.io/dagger/@v/v0.20.6.zip: 503 Service Unavailable
Error: failed to apply generated code: exit code: 1
"""

DIAL_TIMEOUT = """\
go: dagger.io/dagger@v0.20.6: Get "https://proxy.golang.org/dagger.io/dagger/@v/list": \
dial tcp 192.0.2.23:443: i/o timeout
Error: failed to apply generated code: exit code: 1
"""


def classify(text):
    """Return True when the classifier calls this failure retryable."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
        handle.write(text)
        path = handle.name
    try:
        return subprocess.run([str(CLASSIFIER), path]).returncode == 0
    finally:
        os.unlink(path)


class ClassifierTest(unittest.TestCase):
    def test_a_checksum_stream_reset_is_retryable(self):
        self.assertTrue(
            classify(SUMDB_STREAM_RESET),
            "the sum.golang.org stream reset must be retryable; it is a dropped "
            "connection, and nothing about the module changed between attempts",
        )

    def test_a_compile_error_is_not_retryable(self):
        self.assertFalse(
            classify(UNDEFINED_SYMBOL),
            "an undefined symbol must not be retried: three more attempts prove "
            "only that a compile error is still a compile error",
        )

    def test_a_proxy_refusing_service_is_retryable(self):
        self.assertTrue(classify(PROXY_503))

    def test_a_transport_timeout_is_retryable(self):
        self.assertTrue(classify(DIAL_TIMEOUT))

    def test_a_missing_file_is_neither_answer(self):
        """Exit 2 is the third answer: the classifier could not be asked.

        It must not collapse into "not retryable", which would be a real
        verdict derived from a broken call.
        """
        result = subprocess.run([str(CLASSIFIER), "/nonexistent/develop.log"],
                                capture_output=True)
        self.assertEqual(result.returncode, 2)


class WrapperTest(unittest.TestCase):
    """Drives the wrapper with a fake `dagger` on PATH.

    These tests exist for one reason: the wrapper pipes dagger's output through
    tee so it reaches both the log and the job console, and tee succeeds
    whatever it is piped. A wrapper that reported the tee's status would report
    every failed develop as a success — a tool that could not run reading as
    clean, in the one step that every later `dagger call` depends on.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.bin = Path(self.tmp) / "bin"
        self.bin.mkdir()

    def fake_dagger(self, body):
        path = self.bin / "dagger"
        path.write_text("#!/usr/bin/env bash\n" + textwrap.dedent(body))
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def run_wrapper(self):
        env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}")
        return subprocess.run([str(WRAPPER), self.tmp], env=env,
                              capture_output=True, text=True, timeout=180)

    def test_a_failing_develop_fails_the_step(self):
        self.fake_dagger("""
            echo './dagger.gen.go:64:10: undefined: Security'
            exit 1
        """)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0,
                            "a failed develop that exits 0 makes every later "
                            "dagger call run against an SDK that was never generated")

    def test_a_compile_error_is_reported_without_burning_the_budget(self):
        counter = Path(self.tmp) / "attempts"
        self.fake_dagger(f"""
            echo x >> {counter}
            echo './dagger.gen.go:64:10: undefined: Security'
            exit 1
        """)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(counter.read_text().count("x"), 1,
                         "a non-fetch failure must be reported on the first attempt")
        self.assertIn("not a transient fetch fault", result.stdout)

    def test_a_fetch_fault_is_retried_and_then_named(self):
        counter = Path(self.tmp) / "attempts"
        self.fake_dagger(f"""
            echo x >> {counter}
            echo 'reading https://sum.golang.org/tile/8/0/x205/155: stream error: stream ID 23; INTERNAL_ERROR; received from peer'
            exit 1
        """)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(counter.read_text().count("x"), 4,
                         "a fetch fault must use the whole retry budget")
        self.assertIn("could not fetch its modules", result.stdout)

    def test_a_fetch_fault_that_clears_succeeds(self):
        counter = Path(self.tmp) / "attempts"
        self.fake_dagger(f"""
            echo x >> {counter}
            if [ "$(wc -l < {counter})" -le 1 ]; then
                echo 'reading https://sum.golang.org/tile/8/0/x205/155: stream error: stream ID 23; INTERNAL_ERROR; received from peer'
                exit 1
            fi
            echo 'generated'
        """)
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("succeeded on attempt 2", result.stdout)


if __name__ == "__main__":
    unittest.main()
