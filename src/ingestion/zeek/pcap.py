from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class PcapRunResult:
    run_id: str
    pcap_path: str
    output_dir: str
    zeek_bin: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    started_at: str
    completed_at: str
    ok: bool
    log_files: list[str]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_zeek_on_pcap(
    *,
    pcap_path: Path,
    output_root: Path,
    zeek_bin: str = "zeek",
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> PcapRunResult:
    pcap_path = Path(pcap_path).resolve()
    output_root = Path(output_root).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    if shutil.which(zeek_bin) is None:
        # also allow absolute path
        if not Path(zeek_bin).exists():
            raise FileNotFoundError(f"Zeek binary not found: {zeek_bin}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + sha256_file(pcap_path)[:12]
    out_dir = output_root / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [zeek_bin, "-C", "-r", str(pcap_path), "LogAscii::use_json=T"]
    if extra_args:
        cmd.extend(extra_args)

    started_at = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(
        cmd,
        cwd=str(out_dir),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    completed_at = datetime.now(timezone.utc).isoformat()
    log_files = sorted([p.name for p in out_dir.glob("*.log")])
    result = PcapRunResult(
        run_id=run_id,
        pcap_path=str(pcap_path),
        output_dir=str(out_dir),
        zeek_bin=zeek_bin,
        command=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout[-10000:],
        stderr=proc.stderr[-10000:],
        started_at=started_at,
        completed_at=completed_at,
        ok=proc.returncode == 0,
        log_files=log_files,
    )
    (out_dir / "run_meta.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return result


def run_zeek_on_pcap_docker(
    *,
    pcap_path: Path,
    output_root: Path,
    docker_bin: str = "docker",
    image: str = "zeek/zeek:latest",
    timeout: int = 300,
) -> PcapRunResult:
    """Run Zeek on a PCAP using Docker. Useful on Windows where Zeek isn't installed natively."""
    pcap_path = Path(pcap_path).resolve()
    output_root = Path(output_root).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    if shutil.which(docker_bin) is None:
        raise FileNotFoundError(f"Docker binary not found: {docker_bin}")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + sha256_file(pcap_path)[:12]
    out_dir = output_root / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # Mount pcap dir read-only and output dir writable. Run zeek in output dir.
    pcap_dir = pcap_path.parent
    pcap_name = pcap_path.name
    cmd = [
        docker_bin, "run", "--rm",
        "-v", f"{pcap_dir}:/pcap:ro",
        "-v", f"{out_dir}:/logs",
        "-w", "/logs",
        image,
        "zeek", "-C", "-r", f"/pcap/{pcap_name}", "LogAscii::use_json=T",
    ]

    started_at = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    completed_at = datetime.now(timezone.utc).isoformat()
    log_files = sorted([p.name for p in out_dir.glob("*.log")])
    result = PcapRunResult(
        run_id=run_id,
        pcap_path=str(pcap_path),
        output_dir=str(out_dir),
        zeek_bin=f"{docker_bin}:{image}",
        command=cmd,
        returncode=proc.returncode,
        stdout=proc.stdout[-10000:],
        stderr=proc.stderr[-10000:],
        started_at=started_at,
        completed_at=completed_at,
        ok=proc.returncode == 0 and len(log_files) > 0,
        log_files=log_files,
    )
    (out_dir / "run_meta.json").write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
    return result
