"""Tests for scripts/dvc_remote.py.

The reported failure (``extra keys not allowed @ data['remote']['origin']
['access_key_id']``) comes from DVC validating remote options against the remote
type implied by its URL: this project's remote is an HTTPS DagsHub DVC endpoint,
so S3-only keys are invalid and DVC refuses to start at all.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dvc_remote.py"
HTTP_URL = "https://dagshub.com/pujanpandey012/Network-Intrusion-Detection-Advanced-MLOps.dvc"
SECRET = "super-secret-dagshub-token"


def load_module():
    spec = importlib.util.spec_from_file_location("dvc_remote", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["dvc_remote"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def dvc_remote():
    return load_module()


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".dvc").mkdir()
    (tmp_path / ".dvc" / "config").write_text(
        f"[core]\n    remote = origin\n\n['remote \"origin\"']\n    url = {HTTP_URL}\n", encoding="utf-8"
    )
    return tmp_path


def write_local(repo: Path, body: str) -> Path:
    path = repo / ".dvc" / "config.local"
    path.write_text(body, encoding="utf-8")
    return path


POISONED = f"['remote \"origin\"']\n    access_key_id = {SECRET}\n    secret_access_key = {SECRET}\n"


def test_check_flags_s3_keys_on_an_http_remote(dvc_remote, repo, capsys):
    write_local(repo, POISONED)

    state = dvc_remote.status(repo)

    assert state.kind == "http"
    assert state.ok is False
    assert any("access_key_id" in problem for problem in state.problems)
    assert dvc_remote.main(["--root", str(repo), "--check"]) == 1
    assert SECRET not in capsys.readouterr().out


def test_fix_removes_only_the_invalid_keys_and_keeps_the_url(dvc_remote, repo):
    write_local(repo, POISONED + "    jobs = 4\n")
    config_before = (repo / ".dvc" / "config").read_text(encoding="utf-8")

    removed = dvc_remote.sanitize(repo)

    assert removed == ["access_key_id", "secret_access_key"]
    entries = dvc_remote.LocalConfig.load(repo / ".dvc" / "config.local").entries()
    assert "access_key_id" not in entries
    assert "secret_access_key" not in entries
    assert entries["jobs"] == "4"
    assert (repo / ".dvc" / "config").read_text(encoding="utf-8") == config_before
    assert dvc_remote.status(repo).ok is True


def test_env_token_is_applied_as_basic_auth_never_printed(dvc_remote, repo, monkeypatch, capsys):
    write_local(repo, POISONED)
    monkeypatch.setenv("DAGSHUB_USER_TOKEN", SECRET)
    monkeypatch.delenv("DAGSHUB_USERNAME", raising=False)

    assert dvc_remote.main(["--root", str(repo), "--fix"]) == 0
    out = capsys.readouterr().out

    entries = dvc_remote.LocalConfig.load(repo / ".dvc" / "config.local").entries()
    assert entries == {"auth": "basic", "user": "pujanpandey012", "password": SECRET}
    assert SECRET not in out
    assert dvc_remote.status(repo).ok is True


def test_an_existing_password_is_not_overwritten(dvc_remote, repo, monkeypatch):
    write_local(repo, "['remote \"origin\"']\n    auth = basic\n    user = someone\n    password = stored\n")
    monkeypatch.setenv("DAGSHUB_USER_TOKEN", SECRET)

    applied, injected = dvc_remote.apply_env_credentials(repo)

    assert applied == []
    assert injected is False
    assert dvc_remote.LocalConfig.load(repo / ".dvc" / "config.local").entries()["password"] == "stored"


def test_s3_remote_keeps_access_keys_and_drops_http_keys(dvc_remote, tmp_path):
    (tmp_path / ".dvc").mkdir()
    (tmp_path / ".dvc" / "config").write_text(
        "[core]\n    remote = origin\n\n['remote \"origin\"']\n    url = s3://dvc\n", encoding="utf-8"
    )
    write_local(tmp_path, "['remote \"origin\"']\n    access_key_id = AKIA\n    secret_access_key = s\n    auth = basic\n")

    assert dvc_remote.status(tmp_path).kind == "s3"
    assert dvc_remote.sanitize(tmp_path) == ["auth"]
    entries = dvc_remote.LocalConfig.load(tmp_path / ".dvc" / "config.local").entries()
    assert entries["access_key_id"] == "AKIA"


def test_local_url_override_wins(dvc_remote, repo):
    write_local(repo, "['remote \"origin\"']\n    url = /mnt/models\n")

    assert dvc_remote.remote_url(repo) == "/mnt/models"
    assert dvc_remote.status(repo).kind == "local"


def test_clear_credentials_leaves_the_url_alone(dvc_remote, repo):
    write_local(repo, "['remote \"origin\"']\n    auth = basic\n    user = u\n    password = p\n    url = /tmp/x\n")

    removed = dvc_remote.clear_credentials(repo)

    assert removed == ["auth", "password", "user"]
    assert dvc_remote.LocalConfig.load(repo / ".dvc" / "config.local").entries() == {"url": "/tmp/x"}


requires_dvc = pytest.mark.skipif(shutil.which("dvc") is None, reason="dvc binary not installed")


@requires_dvc
def test_real_dvc_parses_the_repaired_config(dvc_remote, tmp_path):
    """End to end with the real binary: the error disappears after sanitize."""

    repo = tmp_path / "dvc-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["dvc", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["dvc", "remote", "add", "origin", HTTP_URL], cwd=repo, check=True)
    write_local(repo, POISONED)

    broken = subprocess.run(["dvc", "status"], cwd=repo, capture_output=True, text=True, check=False)
    assert "extra keys not allowed" in broken.stderr

    dvc_remote.sanitize(repo)

    fixed = subprocess.run(["dvc", "status"], cwd=repo, capture_output=True, text=True, check=False)
    assert "extra keys not allowed" not in fixed.stderr
    assert "configuration error" not in fixed.stderr
