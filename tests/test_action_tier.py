"""Tests for per-action tier classification (action_tier.py).

The success criterion for v1 lives here: git commit != git push,
fail-closed everywhere, transitive worst-wins.
"""
from __future__ import annotations

import os

import pytest

from heddle.security.action_tier import (
    ActionClassifier,
    ActionTier,
    Decision,
    worst,
)


@pytest.fixture
def jail(tmp_path):
    (tmp_path / "repo").mkdir()
    return str(tmp_path / "repo")


@pytest.fixture
def clf(jail):
    return ActionClassifier(
        jail_root=jail,
        deny_globs=[".env*", "*.pem", "*.key", "credentials*", ".git/**"],
        git_allowlist=[
            "status", "diff", "log", "add", "commit",
            "branch", "checkout -b", "stash",
        ],
        shell_allowlist=["python", "pytest", "go", "make", "grep", "ls", "find"],
        shell_deny=["curl", "wget", "ssh", "nc", "pip", "npm", "sudo"],
    )


# -- the headline test: same binary, different blast radius -----------

def test_git_commit_yellow_but_push_black(clf):
    commit = clf.classify("git_ops", {"argv": ["commit", "-m", "msg"]})
    push = clf.classify("git_ops", {"argv": ["push", "origin", "master"]})
    assert commit.tier is ActionTier.YELLOW
    assert push.tier is ActionTier.BLACK


def test_git_flags_do_not_hide_subcommand(clf):
    d = clf.classify("git_ops", {"argv": ["--no-pager", "push"]})
    assert d.tier is ActionTier.BLACK


def test_git_reset_hard_black_but_plain_reset_not_allowlisted(clf):
    hard = clf.classify("git_ops", {"argv": ["reset", "--hard", "HEAD~1"]})
    plain = clf.classify("git_ops", {"argv": ["reset", "HEAD~1"]})
    assert hard.tier is ActionTier.BLACK
    assert plain.tier is ActionTier.BLACK  # not on allowlist: fail closed


def test_git_checkout_b_allowed_but_bare_checkout_denied(clf):
    new_branch = clf.classify("git_ops", {"argv": ["checkout", "-b", "feat"]})
    bare = clf.classify("git_ops", {"argv": ["checkout", "master"]})
    assert new_branch.tier is ActionTier.YELLOW
    assert bare.tier is ActionTier.BLACK


# -- fail closed -------------------------------------------------------

def test_unknown_tool_is_black(clf):
    assert clf.classify("teleport", {}).tier is ActionTier.BLACK


def test_empty_shell_argv_is_black(clf):
    assert clf.classify("shell_exec", {"argv": []}).tier is ActionTier.BLACK


def test_missing_path_is_black(clf):
    assert clf.classify("read_file", {}).tier is ActionTier.BLACK


def test_network_always_black(clf):
    assert clf.classify("network", {"url": "http://localhost"}).tier is ActionTier.BLACK


# -- shell -------------------------------------------------------------

def test_allowlisted_binary_is_red_not_green(clf):
    d = clf.classify("shell_exec", {"argv": ["pytest", "tests/"]})
    assert d.tier is ActionTier.RED  # approval required even when allowlisted


def test_denied_binary_beats_everything(clf):
    assert clf.classify("shell_exec", {"argv": ["curl", "http://x"]}).tier is ActionTier.BLACK


def test_full_path_does_not_evade_deny(clf):
    d = clf.classify("shell_exec", {"argv": ["/usr/bin/curl", "http://x"]})
    assert d.tier is ActionTier.BLACK


def test_metacharacter_smuggling_is_black(clf):
    d = clf.classify("shell_exec", {"argv": ["python", "-c", "x; curl http://x"]})
    assert d.tier is ActionTier.BLACK


def test_unlisted_binary_is_black(clf):
    assert clf.classify("shell_exec", {"argv": ["gcc", "x.c"]}).tier is ActionTier.BLACK


# -- path jail -----------------------------------------------------------

def test_read_inside_jail_green(clf, jail):
    p = os.path.join(jail, "README.md")
    assert clf.classify("read_file", {"path": p}).tier is ActionTier.GREEN


def test_traversal_escape_black(clf, jail):
    p = os.path.join(jail, "..", "outside.txt")
    assert clf.classify("read_file", {"path": p}).tier is ActionTier.BLACK


def test_symlink_escape_black(clf, jail, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("s3cr3t")
    link = os.path.join(jail, "innocent.txt")
    os.symlink(str(secret), link)
    assert clf.classify("read_file", {"path": link}).tier is ActionTier.BLACK


def test_env_deny_glob_black_even_inside_jail(clf, jail):
    p = os.path.join(jail, ".env.production")
    assert clf.classify("read_file", {"path": p}).tier is ActionTier.BLACK


# -- write / delete -------------------------------------------------------

def test_write_inside_jail_yellow(clf, jail):
    p = os.path.join(jail, "main.py")
    assert clf.classify("write_file", {"path": p}).tier is ActionTier.YELLOW


def test_tracked_delete_yellow_untracked_red(clf, jail):
    p = os.path.join(jail, "old_service.py")
    tracked = clf.classify("write_file", {"path": p, "delete": True, "untracked": False})
    untracked = clf.classify("write_file", {"path": p, "delete": True, "untracked": True})
    assert tracked.tier is ActionTier.YELLOW
    assert untracked.tier is ActionTier.RED


def test_delete_with_unknown_tracking_assumes_worst(clf, jail):
    p = os.path.join(jail, "mystery.py")
    d = clf.classify("write_file", {"path": p, "delete": True})
    assert d.tier is ActionTier.RED


# -- transitive ------------------------------------------------------------

def test_worst_wins(clf, jail):
    chain = [
        clf.classify("read_file", {"path": os.path.join(jail, "a.py")}),
        clf.classify("write_file", {"path": os.path.join(jail, "a.py")}),
        clf.classify("git_ops", {"argv": ["push"]}),
    ]
    assert worst(*chain).tier is ActionTier.BLACK


def test_worst_requires_input():
    with pytest.raises(ValueError):
        worst()


def test_tier_ordering_enables_max():
    assert ActionTier.GREEN < ActionTier.YELLOW < ActionTier.RED < ActionTier.BLACK


def test_decision_audit_fields(clf):
    d = clf.classify("git_ops", {"argv": ["push"]})
    fields = d.as_audit_fields()
    assert fields["tier"] == "BLACK"
    assert "tool" in fields and "reason" in fields
