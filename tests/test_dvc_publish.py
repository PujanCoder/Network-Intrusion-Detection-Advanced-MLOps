"""Tests for scripts/dvc_publish.py: relock, gating and remote verification."""

from __future__ import annotations

import functools
import hashlib
import http.server
import importlib.util
import json
import socket
import sys
import threading
from pathlib import Path

import joblib
import pandas as pd
import pytest
import yaml
from sklearn.ensemble import RandomForestClassifier

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dvc_publish.py"
HTTP_URL = "https://dagshub.com/pujanpandey012/Network-Intrusion-Detection-Advanced-MLOps.dvc"

LOCK = """schema: '2.0'
stages:
  ml_pipeline:
    cmd: python -m src.pipelines.pipeline
    deps:
    - path: src/models/tracking.py
      hash: md5
      md5: '1111111111111111111111111111aaaa'
      size: 1531
    params:
      params.yaml:
        model:
          path: models/best_model.joblib
          preprocessor_path: models/preprocessor.joblib
    outs:
    - path: data/processed/cleaned_dataset.csv
      hash: md5
      md5: '22222222222222222222222222222222'
      size: 81556378
    - path: models/best_model.joblib
      hash: md5
      md5: '33333333333333333333333333333333'
      size: 1
    - path: models/preprocessor.joblib
      hash: md5
      md5: '44444444444444444444444444444444'
      size: 1
  validate_preprocessor:
    cmd: python -m src.serving.validate_artifacts
    deps:
    - path: models/best_model.joblib
      hash: md5
      md5: '33333333333333333333333333333333'
      size: 1
"""


def load_module():
    spec = importlib.util.spec_from_file_location("dvc_publish", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["dvc_publish"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def publisher():
    return load_module()


@pytest.fixture
def repo(tmp_path, monkeypatch, publisher):
    (tmp_path / ".dvc").mkdir()
    (tmp_path / ".dvc" / "config").write_text(
        f"[core]\n    remote = origin\n\n['remote \"origin\"']\n    url = {HTTP_URL}\n", encoding="utf-8"
    )
    (tmp_path / "dvc.lock").write_text(LOCK, encoding="utf-8")
    (tmp_path / "models").mkdir()
    monkeypatch.setattr(publisher, "ROOT", tmp_path)
    monkeypatch.delenv("DAGSHUB_USER_TOKEN", raising=False)
    monkeypatch.delenv("DAGSHUB_TOKEN", raising=False)
    return tmp_path


class Passthrough:
    """Module-level so joblib can pickle it."""

    def __init__(self, columns):
        self.columns = columns

    def transform(self, frame):
        return frame[self.columns]


def write_artifacts(repo: Path) -> tuple[Path, Path]:
    columns = ["f1", "f2", "f3"]
    frame = pd.DataFrame(
        [{column: float(index + offset) for column in columns} for index, offset in enumerate(range(12))]
    )
    labels = ["BENIGN" if index % 2 else "DDoS" for index in range(12)]
    model = RandomForestClassifier(n_estimators=3, random_state=0).fit(frame, labels)

    model_path = repo / "models" / "best_model.joblib"
    preprocessor_path = repo / "models" / "preprocessor.joblib"
    joblib.dump(model, model_path)
    joblib.dump(
        {"preprocessor": Passthrough(columns), "feature_order": columns, "model_features": columns},
        preprocessor_path,
    )
    return model_path, preprocessor_path


def test_relock_updates_only_the_two_artifacts_and_their_dependents(publisher, repo):
    model_path, preprocessor_path = write_artifacts(repo)

    locked = publisher.relock((model_path, preprocessor_path))

    payload = yaml.safe_load((repo / "dvc.lock").read_text(encoding="utf-8"))
    stages = payload["stages"]
    model_md5 = hashlib.md5(model_path.read_bytes()).hexdigest()
    pre_md5 = hashlib.md5(preprocessor_path.read_bytes()).hexdigest()

    outs = {item["path"]: item for item in stages["ml_pipeline"]["outs"]}
    assert outs["models/best_model.joblib"]["md5"] == model_md5
    assert outs["models/best_model.joblib"]["size"] == model_path.stat().st_size
    assert outs["models/preprocessor.joblib"]["md5"] == pre_md5
    # untouched neighbours
    assert outs["data/processed/cleaned_dataset.csv"]["md5"] == "2" * 32
    assert stages["ml_pipeline"]["deps"][0]["md5"] == "1111111111111111111111111111aaaa"
    # the params block is not an output entry and must survive verbatim
    def params_region(text: str) -> str:
        return text.split("    params:")[1].split("    outs:")[0]

    assert params_region((repo / "dvc.lock").read_text(encoding="utf-8")) == params_region(LOCK)
    assert stages["ml_pipeline"]["params"]["params.yaml"]["model"]["path"] == "models/best_model.joblib"
    # the validator stage depends on the model, so its dep hash follows
    assert stages["validate_preprocessor"]["deps"][0]["md5"] == model_md5
    assert locked["models/best_model.joblib"]["md5"] == model_md5


def test_relock_stores_cache_objects_in_the_modern_layout(publisher, repo):
    model_path, preprocessor_path = write_artifacts(repo)

    publisher.relock((model_path, preprocessor_path))

    for path in (model_path, preprocessor_path):
        md5 = hashlib.md5(path.read_bytes()).hexdigest()
        assert (repo / ".dvc" / "cache" / "files" / "md5" / md5[:2] / md5[2:]).is_file()


def test_relock_refuses_to_write_when_an_entry_is_missing(publisher, repo, monkeypatch):
    model_path, preprocessor_path = write_artifacts(repo)
    (repo / "dvc.lock").write_text("schema: '2.0'\nstages: {}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="could not relock"):
        publisher.relock((model_path, preprocessor_path))


def test_publish_stops_at_missing_credentials_for_an_authenticated_remote(publisher, repo):
    write_artifacts(repo)

    report = publisher.publish(dry_run=True)

    assert report["exit_code"] == 2
    assert any(step["step"] == "credentials" and step["outcome"] == "missing" for step in report["steps"])


def test_publish_stops_when_the_artifacts_are_missing(publisher, repo):
    (repo / ".dvc" / "config.local").write_text(
        "['remote \"origin\"']\n    url = /tmp/does-not-matter\n", encoding="utf-8"
    )

    report = publisher.publish(dry_run=True)

    assert report["exit_code"] == 3
    assert any(step["step"] == "artifacts" and step["outcome"] == "unusable" for step in report["steps"])


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D102 - silence the test server
        pass


@pytest.fixture
def http_remote(tmp_path):
    root = tmp_path / "remote"
    root.mkdir()
    handler = functools.partial(QuietHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield root, f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_head_verification_accepts_the_real_object(publisher, http_remote, tmp_path, monkeypatch):
    serve_root, url = http_remote
    repo = tmp_path / "repo"
    (repo / ".dvc").mkdir(parents=True)
    (repo / ".dvc" / "config").write_text(
        f"[core]\n    remote = origin\n\n['remote \"origin\"']\n    url = {url}\n", encoding="utf-8"
    )
    monkeypatch.setattr(publisher, "ROOT", repo)
    monkeypatch.delenv("DAGSHUB_USER_TOKEN", raising=False)

    payload = b"model-bytes" * 100
    md5 = hashlib.md5(payload).hexdigest()
    target = serve_root / "files" / "md5" / md5[:2] / md5[2:]
    target.parent.mkdir(parents=True)
    target.write_bytes(payload)

    assert publisher.remote_object_url(md5) == f"{url}/files/md5/{md5[:2]}/{md5[2:]}"
    present, detail = publisher.verify_remote_object(md5, len(payload))
    assert present is True
    assert "200" in detail


def test_head_verification_rejects_a_size_mismatch_and_a_missing_object(publisher, http_remote, tmp_path, monkeypatch):
    serve_root, url = http_remote
    repo = tmp_path / "repo2"
    (repo / ".dvc").mkdir(parents=True)
    (repo / ".dvc" / "config").write_text(
        f"[core]\n    remote = origin\n\n['remote \"origin\"']\n    url = {url}\n", encoding="utf-8"
    )
    monkeypatch.setattr(publisher, "ROOT", repo)
    monkeypatch.delenv("DAGSHUB_USER_TOKEN", raising=False)

    payload = b"abc"
    md5 = hashlib.md5(payload).hexdigest()
    target = serve_root / "files" / "md5" / md5[:2] / md5[2:]
    target.parent.mkdir(parents=True)
    target.write_bytes(payload)

    truncated, _ = publisher.verify_remote_object(md5, len(payload) + 10)
    absent, detail = publisher.verify_remote_object("f" * 32, 1)

    assert truncated is False
    assert absent is False
    assert "404" in detail


def test_uncommitted_lock_is_flagged_after_a_successful_publish(publisher, repo, capsys):
    import subprocess

    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], cwd=repo, check=True
    )
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"], cwd=repo, check=True
    )
    model_path, preprocessor_path = write_artifacts(repo)

    assert publisher.lock_needs_commit() is False

    publisher.relock((model_path, preprocessor_path))

    assert publisher.lock_needs_commit() is True
    publisher.print_report({"ok": True, "exit_code": 0, "steps": []})
    assert "NEXT: dvc.lock changed" in capsys.readouterr().out


def test_report_is_json_serialisable(publisher, repo, capsys):
    write_artifacts(repo)

    assert publisher.main(["--dry-run", "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["exit_code"] == 2
    assert isinstance(payload["steps"], list)
