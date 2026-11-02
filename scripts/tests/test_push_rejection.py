"""Regression proof for scripts/ci/classify-push-rejection.sh.

The release job used to treat every rejected push as a lost race. On
2026-08-03 that misclassified a repository-ruleset refusal five times in a
row — each attempt re-derived the version bump, re-ran the coherence gate and
logged "main advanced; re-deriving against the new tip", then the job reported
"failed to push version pins after 5 attempts". The remote had in fact said
exactly what was wrong on the first try.

Every fixture below is real captured stderr, not a paraphrase:

* RULESET_REFUSAL — the CD run of the v1.11.0 release attempt.
* NON_FAST_FORWARD — produced locally by pushing a diverged branch to a bare
  repository with the git shipped on this machine.

The classifier is a regex against git's wording, so a git upgrade that
rephrases a rejection must fail here rather than mislabel a release.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLASSIFIER = REPO_ROOT / "scripts" / "ci" / "classify-push-rejection.sh"

RULESET_REFUSAL = """\
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: Review all repository rules at https://github.com/context-and-oss/cicd/rules?ref=refs%2Fheads%2Fmain
remote:
remote: - Required status check "ci" is expected.
remote:
To https://github.com/context-and-oss/cicd.git
 ! [remote rejected] HEAD -> main (push declined due to repository rule violations)
error: failed to push some refs to 'https://github.com/context-and-oss/cicd.git'
"""

NON_FAST_FORWARD = """\
To /tmp/pushfix/remote.git
 ! [rejected]        HEAD -> main (non-fast-forward)
error: failed to push some refs to '/tmp/pushfix/remote.git'
hint: Updates were rejected because the tip of your current branch is behind
hint: its remote counterpart. If you want to integrate the remote changes,
hint: use 'git pull' before pushing again.
hint: See the 'Note about fast-forwards' in 'git push --help' for details.
"""

FETCH_FIRST = """\
To https://github.com/context-and-oss/cicd.git
 ! [rejected]        HEAD -> main (fetch first)
error: failed to push some refs to 'https://github.com/context-and-oss/cicd.git'
hint: Updates were rejected because the remote contains work that you do not
hint: have locally.
"""

STALE_INFO = """\
To https://github.com/context-and-oss/cicd.git
 ! [rejected]        HEAD -> main (stale info)
error: failed to push some refs to 'https://github.com/context-and-oss/cicd.git'
"""

PROTECTED_BRANCH = """\
remote: error: GH006: Protected branch update failed for refs/heads/main.
remote: error: Required status check "lint-repo" is expected.
To https://github.com/context-and-oss/cicd.git
 ! [remote rejected] HEAD -> main (protected branch hook declined)
error: failed to push some refs to 'https://github.com/context-and-oss/cicd.git'
"""

PERMISSION_DENIED = """\
remote: Permission to context-and-oss/cicd.git denied to github-actions[bot].
fatal: unable to access 'https://github.com/context-and-oss/cicd.git/': The requested URL returned error: 403
"""

WORKFLOW_SCOPE = """\
! [remote rejected] HEAD -> main (refusing to allow an OAuth App to create or update workflow `.github/workflows/cd.yml` without `workflow` scope)
error: failed to push some refs to 'https://github.com/context-and-oss/cicd.git'
"""

TRANSPORT_FAILURE = """\
fatal: unable to access 'https://github.com/context-and-oss/cicd.git/': Could not resolve host: github.com
"""


def classify(stderr: str):
    """Return the classifier's exit status for this captured stderr."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write(stderr)
        path = fh.name
    try:
        return subprocess.run(
            ["bash", str(CLASSIFIER), path],
            capture_output=True,
            text=True,
        ).returncode
    finally:
        Path(path).unlink()


class TestRetryableRejections(unittest.TestCase):
    """The three rejections that genuinely mean "the remote ref moved"."""

    def test_non_fast_forward_is_retryable(self):
        self.assertEqual(classify(NON_FAST_FORWARD), 0)

    def test_fetch_first_is_retryable(self):
        self.assertEqual(classify(FETCH_FIRST), 0)

    def test_stale_info_is_retryable(self):
        self.assertEqual(classify(STALE_INFO), 0)


class TestTerminalRejections(unittest.TestCase):
    """Everything a retry cannot fix must be reported, not re-attempted."""

    def test_ruleset_refusal_is_terminal(self):
        # The exact failure that burned five attempts on 2026-08-03.
        self.assertEqual(classify(RULESET_REFUSAL), 1)

    def test_protected_branch_refusal_is_terminal(self):
        self.assertEqual(classify(PROTECTED_BRANCH), 1)

    def test_permission_denied_is_terminal(self):
        self.assertEqual(classify(PERMISSION_DENIED), 1)

    def test_missing_workflow_scope_is_terminal(self):
        self.assertEqual(classify(WORKFLOW_SCOPE), 1)

    def test_transport_failure_is_terminal(self):
        # Deliberate: the `git fetch` opening each attempt does not tolerate a
        # transport failure either, so the push loop does not pretend to.
        self.assertEqual(classify(TRANSPORT_FAILURE), 1)

    def test_empty_stderr_is_terminal(self):
        # A push that failed while saying nothing is not evidence of a race.
        self.assertEqual(classify(""), 1)


class TestClassifierContract(unittest.TestCase):
    def test_missing_file_is_a_usage_error_not_a_verdict(self):
        # Exit 2 keeps "I could not read the log" distinguishable from
        # "not retryable" — a caller must never read a broken invocation as a
        # classification.
        result = subprocess.run(
            ["bash", str(CLASSIFIER), "/nonexistent/push.log"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)

    def test_no_argument_is_a_usage_error(self):
        result = subprocess.run(
            ["bash", str(CLASSIFIER)], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 2)

    def test_a_rule_name_quoting_a_retryable_reason_stays_terminal(self):
        # Adversarial, and the reason the pattern anchors on the `[rejected]`
        # line: violated-rule names are remote text nobody here controls, so a
        # rule (or a commit subject echoed back) that literally contains
        # "(non-fast-forward)" must not talk a permanent refusal into a retry.
        poisoned = RULESET_REFUSAL.replace(
            'Required status check "ci" is expected.',
            'Commit messages must not say (non-fast-forward).',
        )
        self.assertEqual(classify(poisoned), 1)

    def test_remote_rejected_alone_is_never_retryable(self):
        # `! [remote rejected]` must not be read as `! [rejected]`, whatever
        # reason follows it.
        stderr = (
            " ! [remote rejected] HEAD -> main (fetch first)\n"
            "error: failed to push some refs\n"
        )
        self.assertEqual(classify(stderr), 1)


if __name__ == "__main__":
    unittest.main()
