"""Dataset loaders that map public labelled flow datasets onto the Zeek schema.

Datasets used
-------------
* CICIDS2017  -- ``Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`` (local copy)
* UNSW-NB15   -- official training / testing partitions
* NSL-KDD     -- official ``KDDTrain+`` / ``KDDTest+`` partitions

The loaders only map fields that genuinely exist in each source (see
``src.realtime.features``); nothing is synthesised. Rows are returned with the
shared feature columns plus ``label`` (canonical class), ``dataset`` and
``group`` (a coarse flow signature used for leakage-safe splitting).
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable

import pandas as pd

from src.realtime.config import PROJECT_ROOT
from src.realtime.features import (
    FEATURE_ORDER,
    SERVICE_PORTS,
    UNSW_STATE_MAP,
    _conn_state_code,
    _flags_from_conn_state,
    features_from_cicids,
    features_from_nslkdd,
    features_from_unsw,
)

BENIGN = "BENIGN"

# --------------------------------------------------------------------------- #
# canonical label space
# --------------------------------------------------------------------------- #
CICIDS_LABELS = {
    "BENIGN": BENIGN,
    "DDOS": "DoS",
    "DOS HULK": "DoS",
    "DOS GOLDENEYE": "DoS",
    "DOS SLOWLORIS": "DoS",
    "DOS SLOWHTTPTEST": "DoS",
    "PORTSCAN": "Recon",
    "FTP-PATATOR": "BruteForce",
    "SSH-PATATOR": "BruteForce",
    "WEB ATTACK - BRUTE FORCE": "WebAttack",
    "WEB ATTACK - SQL INJECTION": "WebAttack",
    "WEB ATTACK - XSS": "WebAttack",
    "BOT": "CommandAndControl",
    "INFILTRATION": "Exfiltration",
    "HEARTBLEED": "Exploit",
}

UNSW_LABELS = {
    "NORMAL": BENIGN,
    "BENIGN": BENIGN,
    "DOS": "DoS",
    "DDOS": "DoS",
    "RECONNAISSANCE": "Recon",
    "EXPLOITS": "Exploit",
    "BACKDOOR": "Backdoor",
    "BACKDOORS": "Backdoor",
    "WORMS": "Worm",
    "SHELLCODE": "Exploit",
    "FUZZERS": "Fuzz",
    "ANALYSIS": "Analysis",
    "GENERIC": "Other",
}

NSLKDD_LABELS = {
    "NORMAL": BENIGN,
    # denial of service
    "NEPTUNE": "DoS", "SMURF": "DoS", "POD": "DoS", "TEARDROP": "DoS",
    "LAND": "DoS", "BACK": "DoS", "UDPSTORM": "DoS", "APACHE2": "DoS",
    "PROCESSTABLE": "DoS", "MAILBOMB": "DoS",
    # reconnaissance / scanning
    "PORTSWEEP": "Recon", "IPSWEEP": "Recon", "NMAP": "Recon",
    "SATAN": "Recon", "MSCAN": "Recon", "SAINT": "Recon",
    # credential / web attacks
    "GUESS_PASSWD": "BruteForce", "FTP_WRITE": "BruteForce", "IMAP": "BruteForce",
    "HTTP": "WebAttack", "FTP": "BruteForce", "PHF": "WebAttack",
    "SNMPGUESS": "BruteForce", "SNMPGETATTACK": "BruteForce",
    "WAREZMASTER": "BruteForce", "WAREZCLIENT": "BruteForce",
    "SENDMAIL": "BruteForce", "NAMED": "BruteForce", "XLOCK": "BruteForce",
    "XSNOOP": "BruteForce",
    # exploitation
    "BUFFER_OVERFLOW": "Exploit", "ROOTKIT": "Exploit", "LOADMODULE": "Exploit",
    "PERL": "Exploit", "SQLATTACK": "Exploit", "PS": "Exploit", "XTERM": "Exploit",
    # tunnelling / other
    "HTTPTUNNEL": "CommandAndControl", "WORM": "Worm",
    "SPY": "Other", "USER2ROOT": "Other", "MULTIHOP": "Other",
}

CICIDS_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Fwd Header Length", "Bwd Header Length", "SYN Flag Count", "ACK Flag Count",
    "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "URG Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Label",
]

NSLKDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]


def canonical_label(raw: str | None, mapping: dict[str, str]) -> str:
    if raw is None or (isinstance(raw, float) and math.isnan(raw)):
        return BENIGN
    key = str(raw).strip().upper()
    return mapping.get(key, "Other")


def _bucket(value: float | None) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "na"
    value = float(value)
    if value <= 0:
        return "0"
    return str(int(math.log10(1.0 + value) * 2))


def group_key(features: dict[str, float | None], label: str) -> str:
    """Coarse signature used to keep near-duplicate flows in one split.

    CICIDS2017 and UNSW-NB15 contain many near-identical flows. Splitting on
    this signature prevents the same behaviour appearing in both train and
    test, which would otherwise inflate the measured scores.
    """

    return "|".join(
        [
            label,
            _bucket(features.get("dst_port")),
            _bucket(features.get("duration_s")),
            _bucket(features.get("orig_bytes")),
            _bucket(features.get("resp_bytes")),
            _bucket(features.get("orig_pkts")),
            _bucket(features.get("resp_pkts")),
            _bucket(features.get("conn_state_code")),
            _bucket(features.get("proto_code")),
        ]
    )


def _assemble(rows: Iterable[dict[str, float | None]], labels: Iterable[str], dataset: str) -> pd.DataFrame:
    frame = pd.DataFrame(rows)
    frame["label"] = list(labels)
    frame["dataset"] = dataset
    frame["group"] = [
        group_key(row, label) for row, label in zip(rows, frame["label"])
    ]
    return frame


# --------------------------------------------------------------------------- #
# CICIDS2017
# --------------------------------------------------------------------------- #
def default_cicids_path() -> Path:
    candidates = [
        PROJECT_ROOT / "data" / "raw" / "MachineLearningCSV" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        PROJECT_ROOT / "notebooks" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def load_cicids(path: str | Path | None = None, limit: int | None = None) -> pd.DataFrame:
    path = Path(path) if path else default_cicids_path()
    if not path.exists():
        raise FileNotFoundError(
            f"CICIDS2017 CSV not found at {path}. Fetch it with DVC or place it under data/raw/MachineLearningCSV/."
        )
    try:
        frame = pd.read_csv(path, skipinitialspace=True, nrows=limit, usecols=CICIDS_COLUMNS)
    except ValueError:
        # Some CICIDS mirrors name the duplicated header differently.
        frame = pd.read_csv(path, skipinitialspace=True, nrows=limit)
    frame.columns = [str(column).replace("\ufeff", "").strip() for column in frame.columns]

    rows: list[dict[str, float | None]] = []
    labels: list[str] = []
    for record in frame.to_dict(orient="records"):
        rows.append(features_from_cicids(record))
        labels.append(canonical_label(record.get("Label"), CICIDS_LABELS))
    return _assemble(rows, labels, "CICIDS2017")


# --------------------------------------------------------------------------- #
# UNSW-NB15
# --------------------------------------------------------------------------- #
def _unsw_row(record: dict) -> tuple[dict[str, float | None], str]:
    features = features_from_unsw(record)
    # UNSW stores packet bytes including headers, so IP byte counts equal them.
    features["orig_ip_bytes"] = features.get("orig_bytes")
    features["resp_ip_bytes"] = features.get("resp_bytes")
    label = canonical_label(record.get("attack_cat"), UNSW_LABELS)
    if label == BENIGN and str(record.get("label", "0")).strip() == "1":
        label = "Other"
    return features, label


def load_unsw(directory: str | Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    directory = Path(directory) if directory else PROJECT_ROOT / "data" / "external" / "unsw-nb15"
    train_path = directory / "UNSW_NB15_training-set.csv"
    test_path = directory / "UNSW_NB15_testing-set.csv"
    if not train_path.exists():
        raise FileNotFoundError(f"UNSW-NB15 training set not found at {train_path}")

    train_frame = pd.read_csv(train_path)
    rows, labels = [], []
    for record in train_frame.to_dict(orient="records"):
        features, label = _unsw_row(record)
        rows.append(features)
        labels.append(label)
    train = _assemble(rows, labels, "UNSW-NB15")

    test = None
    if test_path.exists():
        test_frame = pd.read_csv(test_path)
        rows, labels = [], []
        for record in test_frame.to_dict(orient="records"):
            features, label = _unsw_row(record)
            rows.append(features)
            labels.append(label)
        test = _assemble(rows, labels, "UNSW-NB15-test")
    return train, test


# --------------------------------------------------------------------------- #
# NSL-KDD
# --------------------------------------------------------------------------- #
def _nslkdd_frame(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, names=NSLKDD_COLUMNS)
    rows, labels = [], []
    for record in frame.to_dict(orient="records"):
        rows.append(features_from_nslkdd(record))
        labels.append(canonical_label(record.get("label"), NSLKDD_LABELS))
    return _assemble(rows, labels, "NSL-KDD")


def load_nslkdd(directory: str | Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    directory = Path(directory) if directory else PROJECT_ROOT / "data" / "external" / "nsl-kdd"
    train_path = directory / "KDDTrain+.txt"
    test_path = directory / "KDDTest+.txt"
    if not train_path.exists():
        raise FileNotFoundError(f"NSL-KDD training set not found at {train_path}")
    train = _nslkdd_frame(train_path)
    test = _nslkdd_frame(test_path) if test_path.exists() else None
    return train, test


# --------------------------------------------------------------------------- #
# convenience
# --------------------------------------------------------------------------- #
def dataset_paths() -> dict[str, Path]:
    return {
        "cicids2017": default_cicids_path(),
        "unsw_train": PROJECT_ROOT / "data" / "external" / "unsw-nb15" / "UNSW_NB15_training-set.csv",
        "unsw_test": PROJECT_ROOT / "data" / "external" / "unsw-nb15" / "UNSW_NB15_testing-set.csv",
        "nslkdd_train": PROJECT_ROOT / "data" / "external" / "nsl-kdd" / "KDDTrain+.txt",
        "nslkdd_test": PROJECT_ROOT / "data" / "external" / "nsl-kdd" / "KDDTest+.txt",
    }


def available_datasets() -> dict[str, bool]:
    return {name: path.exists() for name, path in dataset_paths().items()}


__all__ = [
    "BENIGN",
    "FEATURE_ORDER",
    "SERVICE_PORTS",
    "UNSW_STATE_MAP",
    "_conn_state_code",
    "_flags_from_conn_state",
    "available_datasets",
    "canonical_label",
    "group_key",
    "load_cicids",
    "load_nslkdd",
    "load_unsw",
]
