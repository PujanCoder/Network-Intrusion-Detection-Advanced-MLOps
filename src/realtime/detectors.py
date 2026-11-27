"""Rule-based detection modules that complement the ML classifier.

The classifier answers "does this flow look malicious and of which family?".
These detectors add the behavioural context a single flow cannot carry:
scan sweeps, floods, brute force, beaconing, exfiltration and DNS tunnelling.

All windows are driven by event timestamps (not wall-clock time), which keeps
results deterministic and makes the modules replay-safe and unit-testable.
"""

from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Iterable

AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 5985, 6379, 8080}
HIGH_RISK_PORTS = {23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 9200, 11211}

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class DetectionHit:
    rule: str
    category: str
    severity: str
    confidence: float
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _coefficient_of_variation(values: Iterable[float]) -> float:
    values = list(values)
    if len(values) < 2:
        return float("inf")
    mean = sum(values) / len(values)
    if mean <= 0:
        return float("inf")
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / mean


class _WindowStore:
    """Bounded per-key event windows.

    Prevents unbounded memory growth on long-running sensors: at most
    ``max_keys`` keys, each holding at most ``max_events`` events.
    """

    def __init__(self, max_keys: int = 4096, max_events: int = 2048) -> None:
        self._max_keys = max_keys
        self._max_events = max_events
        self._data: dict[Any, Deque[tuple[float, Any]]] = {}

    def append(self, key: Any, ts: float, payload: Any, window_s: float) -> Deque[tuple[float, Any]]:
        if key not in self._data:
            if len(self._data) >= self._max_keys:
                # Drop the least recently used key.
                oldest = min(self._data, key=lambda k: self._data[k][-1][0] if self._data[k] else 0.0)
                self._data.pop(oldest, None)
            self._data[key] = deque(maxlen=self._max_events)
        window = self._data[key]
        window.append((ts, payload))
        cutoff = ts - window_s
        while window and window[0][0] < cutoff:
            window.popleft()
        return window

    def get(self, key: Any) -> Deque[tuple[float, Any]]:
        return self._data.get(key, deque())

    def clear(self) -> None:
        self._data.clear()


class DetectorEngine:
    """Evaluates every stored event against the behavioural detectors."""

    def __init__(self, alert_cooldown_s: float = 60.0) -> None:
        self.alert_cooldown_s = alert_cooldown_s
        self._flows = _WindowStore()
        self._dns = _WindowStore()
        self._cooldowns: dict[tuple[str, str], tuple[float, int]] = {}

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    def observe(self, event: Any, features: dict[str, Any] | None = None) -> list[DetectionHit]:
        hits: list[DetectionHit] = []

        if event.log_type == "dns":
            hits.extend(self._dns_detectors(event))
        elif event.log_type == "conn":
            hits.extend(self._conn_detectors(event, features or {}))

        return [hit for hit in hits if self._allow(hit.rule, event, hit)]

    def reset(self) -> None:
        self._flows.clear()
        self._dns.clear()
        self._cooldowns.clear()

    # ------------------------------------------------------------------ #
    # detectors
    # ------------------------------------------------------------------ #
    def _conn_detectors(self, event: Any, features: dict[str, Any]) -> list[DetectionHit]:
        hits: list[DetectionHit] = []
        src = event.src_ip
        dst = event.dst_ip
        if not src or not dst:
            return hits

        payload = {
            "dst": dst,
            "dst_port": event.dst_port,
            "state": event.conn_state,
            "orig_bytes": event.orig_bytes or 0,
            "resp_bytes": event.resp_bytes or 0,
            "syn": features.get("syn_flag") or 0,
            "duration": event.duration or 0.0,
        }

        src_window = self._flows.append(("src", src), event.ts, payload, window_s=600)
        dst_window = self._flows.append(("dst", dst), event.ts, payload, window_s=60)
        pair_key = ("pair", src, dst, event.dst_port)
        pair_window = self._flows.append(pair_key, event.ts, payload, window_s=600)

        # --- port scan: many distinct ports on few hosts -----------------
        recent = [p for ts, p in src_window if event.ts - ts <= 60]
        distinct_ports = {p["dst_port"] for p in recent if p["dst_port"]}
        distinct_hosts = {p["dst"] for p in recent}
        if len(distinct_ports) >= 20 and len(distinct_hosts) <= 3:
            hits.append(
                DetectionHit(
                    rule="port_scan_sweep",
                    category="PortScan",
                    severity="HIGH" if len(distinct_ports) >= 60 else "MEDIUM",
                    confidence=min(0.99, 0.6 + len(distinct_ports) / 200),
                    explanation=(
                        f"{src} probed {len(distinct_ports)} distinct ports on "
                        f"{len(distinct_hosts)} host(s) in 60s"
                    ),
                    evidence={
                        "src_ip": src,
                        "distinct_ports": len(distinct_ports),
                        "distinct_hosts": len(distinct_hosts),
                        "sample_ports": sorted(distinct_ports)[:15],
                        "window_s": 60,
                    },
                )
            )

        # --- host sweep / lateral movement -------------------------------
        if len(distinct_hosts) >= 15 and len(distinct_ports) <= 3:
            hits.append(
                DetectionHit(
                    rule="host_sweep",
                    category="Recon",
                    severity="MEDIUM",
                    confidence=min(0.95, 0.55 + len(distinct_hosts) / 100),
                    explanation=(
                        f"{src} contacted {len(distinct_hosts)} hosts on "
                        f"{len(distinct_ports)} port(s) in 60s"
                    ),
                    evidence={
                        "src_ip": src,
                        "distinct_hosts": len(distinct_hosts),
                        "distinct_ports": len(distinct_ports),
                        "window_s": 60,
                    },
                )
            )

        # --- SYN flood / volumetric DoS ----------------------------------
        syn_only = sum(1 for _, p in dst_window if p["syn"] and p["state"] in {"S0", "REJ"})
        if len(dst_window) >= 100 and syn_only / max(1, len(dst_window)) >= 0.5:
            hits.append(
                DetectionHit(
                    rule="syn_flood",
                    category="DoS",
                    severity="HIGH",
                    confidence=min(0.99, 0.6 + len(dst_window) / 1000),
                    explanation=(
                        f"{len(dst_window)} connections to {dst} in 60s, "
                        f"{syn_only} unanswered/refused (SYN flood pattern)"
                    ),
                    evidence={
                        "dst_ip": dst,
                        "connections": len(dst_window),
                        "syn_unanswered": syn_only,
                        "window_s": 60,
                    },
                )
            )

        # --- brute force against authentication services -----------------
        if event.dst_port in AUTH_PORTS:
            failed = sum(
                1 for _, p in pair_window
                if p["state"] in {"S0", "REJ", "RSTO", "RSTR"} or p["resp_bytes"] == 0
            )
            if len(pair_window) >= 8 and failed / max(1, len(pair_window)) >= 0.5:
                hits.append(
                    DetectionHit(
                        rule="auth_brute_force",
                        category="BruteForce",
                        severity="HIGH",
                        confidence=min(0.97, 0.55 + len(pair_window) / 60),
                        explanation=(
                            f"{len(pair_window)} attempts from {src} to {dst}:{event.dst_port} "
                            f"in 10 min, {failed} without a successful response"
                        ),
                        evidence={
                            "src_ip": src,
                            "dst_ip": dst,
                            "dst_port": event.dst_port,
                            "attempts": len(pair_window),
                            "failed_attempts": failed,
                            "window_s": 600,
                        },
                    )
                )

        # --- C2 beaconing: regular interval, low volume -------------------
        if len(pair_window) >= 6:
            timestamps = [ts for ts, _ in pair_window]
            intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
            if intervals:
                cv = _coefficient_of_variation(intervals)
                avg_bytes = sum(p["orig_bytes"] + p["resp_bytes"] for _, p in pair_window) / len(pair_window)
                if cv < 0.35 and avg_bytes < 10_000:
                    hits.append(
                        DetectionHit(
                            rule="c2_beaconing",
                            category="CommandAndControl",
                            severity="HIGH",
                            confidence=min(0.95, 0.7 + (0.35 - cv)),
                            explanation=(
                                f"{len(pair_window)} regular connections from {src} to "
                                f"{dst}:{event.dst_port} (interval CV {cv:.2f}, "
                                f"avg {avg_bytes:.0f} B/flow)"
                            ),
                            evidence={
                                "src_ip": src,
                                "dst_ip": dst,
                                "dst_port": event.dst_port,
                                "connections": len(pair_window),
                                "interval_cv": round(cv, 3),
                                "mean_interval_s": round(sum(intervals) / len(intervals), 2),
                                "avg_bytes_per_flow": round(avg_bytes, 1),
                                "window_s": 600,
                            },
                        )
                    )

        # --- outbound data exfiltration -----------------------------------
        outbound = sum(p["orig_bytes"] for ts, p in src_window if event.ts - ts <= 60)
        inbound = sum(p["resp_bytes"] for ts, p in src_window if event.ts - ts <= 60)
        if outbound >= 5_000_000 and outbound >= max(1, inbound) * 3:
            hits.append(
                DetectionHit(
                    rule="outbound_exfiltration",
                    category="Exfiltration",
                    severity="CRITICAL",
                    confidence=min(0.97, 0.6 + outbound / 50_000_000),
                    explanation=(
                        f"{src} sent {outbound / 1e6:.1f} MB outbound in 60s "
                        f"({outbound / max(1, inbound):.1f}x inbound volume)"
                    ),
                    evidence={
                        "src_ip": src,
                        "outbound_bytes": outbound,
                        "inbound_bytes": inbound,
                        "window_s": 60,
                    },
                )
            )
        elif (event.orig_bytes or 0) >= 2_000_000 and (event.resp_bytes or 0) < (event.orig_bytes or 0) * 0.1:
            hits.append(
                DetectionHit(
                    rule="large_outbound_flow",
                    category="Exfiltration",
                    severity="MEDIUM",
                    confidence=0.7,
                    explanation=(
                        f"single flow from {src} to {dst} uploaded "
                        f"{(event.orig_bytes or 0) / 1e6:.1f} MB with almost no response"
                    ),
                    evidence={
                        "src_ip": src,
                        "dst_ip": dst,
                        "orig_bytes": event.orig_bytes,
                        "resp_bytes": event.resp_bytes,
                    },
                )
            )

        # --- connection failure anomaly -----------------------------------
        if len(src_window) >= 20:
            failures = sum(1 for _, p in src_window if p["state"] in {"REJ", "RSTO", "RSTR"})
            if failures / len(src_window) >= 0.7:
                hits.append(
                    DetectionHit(
                        rule="connection_failure_ratio",
                        category="SuspiciousConnection",
                        severity="LOW",
                        confidence=0.6,
                        explanation=(
                            f"{failures}/{len(src_window)} recent connections from {src} "
                            f"were reset or refused"
                        ),
                        evidence={
                            "src_ip": src,
                            "connections": len(src_window),
                            "failures": failures,
                        },
                    )
                )

        # --- high-risk service exposed to a remote peer -------------------
        if event.dst_port in HIGH_RISK_PORTS and event.src_ip and event.dst_ip:
            if not _is_private(event.src_ip) and _is_private(event.dst_ip):
                hits.append(
                    DetectionHit(
                        rule="exposed_high_risk_service",
                        category="SuspiciousConnection",
                        severity="MEDIUM",
                        confidence=0.55,
                        explanation=(
                            f"external host {src} reached internal service "
                            f"{dst}:{event.dst_port}"
                        ),
                        evidence={"src_ip": src, "dst_ip": dst, "dst_port": event.dst_port},
                    )
                )

        return hits

    def _dns_detectors(self, event: Any) -> list[DetectionHit]:
        query = str(event.raw.get("query") or "")
        if not event.src_ip or not query:
            return []

        payload = {
            "query": query,
            "qtype": event.raw.get("qtype"),
            "qtype_name": event.raw.get("qtype_name"),
            "length": len(query),
            "entropy": _entropy(query.split(".")[0]),
        }
        window = self._dns.append(("dns", event.src_ip), event.ts, payload, window_s=60)

        if len(window) < 20:
            return []

        labels = [p["query"].split(".")[0] for _, p in window]
        unique_labels = len(set(labels))
        avg_length = sum(p["length"] for _, p in window) / len(window)
        avg_entropy = sum(p["entropy"] for _, p in window) / len(window)

        if avg_length >= 40 or (unique_labels >= 25 and avg_entropy >= 3.2):
            return [
                DetectionHit(
                    rule="dns_tunneling",
                    category="DnsTunneling",
                    severity="HIGH",
                    confidence=min(0.95, 0.6 + avg_entropy / 10),
                    explanation=(
                        f"{event.src_ip} issued {len(window)} DNS queries in 60s "
                        f"(avg name length {avg_length:.0f}, avg label entropy {avg_entropy:.2f})"
                    ),
                    evidence={
                        "src_ip": event.src_ip,
                        "queries": len(window),
                        "unique_labels": unique_labels,
                        "avg_query_length": round(avg_length, 1),
                        "avg_entropy": round(avg_entropy, 2),
                        "window_s": 60,
                    },
                )
            ]
        return []

    # ------------------------------------------------------------------ #
    # alert de-duplication
    # ------------------------------------------------------------------ #
    def _allow(self, rule: str, event: Any, hit: DetectionHit) -> bool:
        key = (rule, f"{event.src_ip}->{event.dst_ip}:{event.dst_port}")
        last = self._cooldowns.get(key)
        if last is not None and event.ts - last[0] < self.alert_cooldown_s:
            self._cooldowns[key] = (last[0], last[1] + 1)
            return False
        occurrences = (last[1] + 1) if last else 1
        self._cooldowns[key] = (event.ts, 0)
        hit.evidence.setdefault("occurrences", occurrences)
        return True


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        first == 10
        or (first == 172 and 16 <= second <= 31)
        or (first == 192 and second == 168)
        or (first == 127)
    )


def combine_severity(model_severity: str | None, hits: list[DetectionHit]) -> str:
    """Final severity = strongest signal from ML and rule detections."""

    levels = [SEVERITY_ORDER.get(model_severity or "INFO", 0)]
    levels.extend(SEVERITY_ORDER.get(hit.severity, 0) for hit in hits)
    level = max(levels)
    for name, value in SEVERITY_ORDER.items():
        if value == level:
            return name
    return "INFO"
