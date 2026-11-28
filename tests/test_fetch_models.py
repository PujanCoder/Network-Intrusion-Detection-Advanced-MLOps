"""Tests for scripts/fetch_models.py, the build-time artefact fetcher.

The script is the only thing standing between a Render build and a missing
model, so its two properties matter more than its internals: it must never fail
a build when the artefact cannot be reached (the service degrades instead), and
it must fail loudly when asked to be strict (CI, pre-deploy checks).
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_models.py"


def load_module():
    spec = importlib.util.spec_from_file_location("fetch_models", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses and pickling look the module up by name
    sys.modules["fetch_models"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fetch(tmp_path, monkeypatch):
    module = load_module()
    root = tmp_path / "app"
    (root / "models" / "zeek").mkdir(parents=True)
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module, "DVC_DIR", root / ".dvc")
    monkeypatch.setattr(
        module,
        "ARTIFACTS",
        (
            module.Artifact("cicids_model", "models/best_model.joblib", True, "dvc"),
            module.Artifact("cicids_preprocessor", "models/preprocessor.joblib", True, "dvc"),
            module.Artifact("zeek_model", "models/zeek/zeek_model.joblib", False, "git"),
        ),
    )
    monkeypatch.delenv("MODEL_ARTIFACTS_URL", raising=False)
    monkeypatch.delenv("MODEL_ARTIFACTS_TOKEN", raising=False)
    monkeypatch.delenv("DAGSHUB_USER_TOKEN", raising=False)
    monkeypatch.delenv("DAGSHUB_USERNAME", raising=False)
    monkeypatch.setenv("PATH", "")  # no dvc binary: the DVC strategy is skipped
    return module


def write_artifacts(root: Path) -> None:
    (root / "models").mkdir(parents=True, exist_ok=True)
    (root / "models" / "best_model.joblib").write_bytes(b"model-bytes")
    (root / "models" / "preprocessor.joblib").write_bytes(b"preprocessor-bytes")
    (root / "models" / "zeek" / "zeek_model.joblib").write_bytes(b"zeek-bytes")


def make_tarball(destination: Path, entries: dict[str, bytes]) -> Path:
    with tarfile.open(destination, "w:gz") as handle:
        for name, payload in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            handle.addfile(info, io.BytesIO(payload))
    return destination


def test_reports_every_artifact_it_checks(fetch, capsys):
    write_artifacts(fetch.ROOT)

    assert fetch.run(check_only=True) == 0

    out = capsys.readouterr().out
    assert "models/best_model.joblib" in out
    assert "models/preprocessor.joblib" in out
    assert "models/zeek/zeek_model.joblib" in out
    assert "MISSING" not in out


def test_missing_artifacts_warn_but_do_not_fail_the_build(fetch, capsys):
    assert fetch.run() == 0

    out = capsys.readouterr().out
    assert "ACTION REQUIRED" in out
    assert "models/best_model.joblib" in out
    assert "no .dvc directory" in out


def test_strict_mode_fails_when_artifacts_are_missing(fetch):
    assert fetch.run(strict=True) == 1


def test_strict_mode_passes_when_artifacts_are_present(fetch):
    write_artifacts(fetch.ROOT)
    assert fetch.run(strict=True) == 0


def test_https_archive_fallback_materialises_both_artifacts(fetch, monkeypatch):
    archive = make_tarball(
        fetch.ROOT.parent / "artifacts.tar.gz",
        {
            "models/best_model.joblib": b"downloaded-model",
            "models/preprocessor.joblib": b"downloaded-preprocessor",
        },
    )
    monkeypatch.setenv("MODEL_ARTIFACTS_URL", archive.as_uri())

    assert fetch.run() == 0

    assert (fetch.ROOT / "models" / "best_model.joblib").read_bytes() == b"downloaded-model"
    assert (fetch.ROOT / "models" / "preprocessor.joblib").read_bytes() == b"downloaded-preprocessor"


def test_archive_entries_cannot_escape_the_project(fetch, monkeypatch, tmp_path):
    archive = make_tarball(
        fetch.ROOT.parent / "evil.tar.gz",
        {"../escaped.txt": b"nope", "models/best_model.joblib": b"model"},
    )
    monkeypatch.setenv("MODEL_ARTIFACTS_URL", archive.as_uri())

    assert fetch.run() == 0  # degraded, not fatal

    assert not (fetch.ROOT.parent / "escaped.txt").exists()
    assert not (fetch.ROOT / "escaped.txt").exists()


def test_credentials_come_from_the_environment_and_are_redacted(fetch, monkeypatch):
    token = "dagshub-token-value"
    (fetch.ROOT / ".dvc").mkdir(parents=True)
    (fetch.ROOT / ".dvc" / "config").write_text(
        "['remote \"origin\"']\n    url = s3://dvc\n"
        "    endpointurl = https://dagshub.com/owner/repo.s3\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DAGSHUB_USER_TOKEN", token)

    report = fetch.Report()
    modes = fetch._credential_modes(report)

    assert fetch._dags_hub_username() == "owner"
    basic = dict(dict(modes)["DagsHub basic auth"])
    assert basic["user"] == "owner"
    assert basic["password"] == token
    assert report.redact(f"leaked {token}") == "leaked ***"
    assert token not in str(modes[0][0])


def test_present_artifact_is_not_downloaded_again(fetch, monkeypatch):
    write_artifacts(fetch.ROOT)
    monkeypatch.setenv("MODEL_ARTIFACTS_URL", "file:///does-not-exist.tar.gz")

    assert fetch.run() == 0

    assert (fetch.ROOT / "models" / "best_model.joblib").read_bytes() == b"model-bytes"


def test_json_report_is_machine_readable(fetch, capsys):
    write_artifacts(fetch.ROOT)

    assert fetch.main(["--check", "--json"]) == 0

    payload = capsys.readouterr().out
    assert '"cicids_model"' in payload
    assert '"missing": []' in payload


def test_script_is_importable_without_side_effects(fetch):
    # Importing must not probe the network or write anything.
    assert os.path.isdir(fetch.ROOT)
    assert not list(fetch.ROOT.rglob("*.joblib"))
