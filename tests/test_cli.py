"""Tests for the Heddle CLI secrets commands."""
import pytest
from click.testing import CliRunner

from heddle.cli import cli
from heddle.security.credentials import CredentialBroker


@pytest.fixture
def broker(tmp_path, monkeypatch):
    b = CredentialBroker(
        secrets_file=tmp_path / "secrets.json",
        policy_file=tmp_path / "policy.json",
    )
    monkeypatch.setattr(
        "heddle.security.credentials.get_credential_broker", lambda: b
    )
    return b


def test_secrets_set_value_argument(broker):
    result = CliRunner().invoke(cli, ["secrets", "set", "api-key", "hunter2"])
    assert result.exit_code == 0
    assert "stored" in result.output
    assert broker._secrets["api-key"].decode() == "hunter2"


def test_secrets_set_stdin(broker):
    result = CliRunner().invoke(
        cli, ["secrets", "set", "api-key", "--stdin"], input="s3cret-from-pipe\n"
    )
    assert result.exit_code == 0
    assert broker._secrets["api-key"].decode() == "s3cret-from-pipe"


def test_secrets_set_stdin_strips_single_trailing_newline_only(broker):
    # Inner whitespace and trailing spaces are part of the secret;
    # only the one newline appended by echo/heredoc is removed.
    result = CliRunner().invoke(
        cli, ["secrets", "set", "api-key", "--stdin"], input="pad ded \n"
    )
    assert result.exit_code == 0
    assert broker._secrets["api-key"].decode() == "pad ded "


def test_secrets_set_rejects_value_and_stdin(broker):
    result = CliRunner().invoke(
        cli, ["secrets", "set", "api-key", "oops", "--stdin"], input="piped\n"
    )
    assert result.exit_code != 0
    assert "not both" in result.output
    assert "api-key" not in broker.list_secrets()


def test_secrets_set_rejects_empty(broker):
    result = CliRunner().invoke(cli, ["secrets", "set", "api-key"])
    assert result.exit_code != 0
    assert "api-key" not in broker.list_secrets()
