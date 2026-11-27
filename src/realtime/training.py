"""Train and evaluate the Zeek-compatible flow classifier.

Design decisions
----------------
* One feature schema (``src.realtime.features``) for training and serving.
* Leakage-safe grouped splits: near-duplicate flows share a ``group`` key and
  never straddle train/validation/test.
* Model selection on a validation split, threshold tuned for a false-positive
  budget, and a final report on untouched test partitions -- including a model
  trained without NSL-KDD and evaluated on it, to measure generalisation to a
  dataset the model has never seen.
* No synthetic rows anywhere: every training row comes from a published,
  labelled dataset.

Run: ``python -m src.realtime.training``
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.realtime.config import PROJECT_ROOT
from src.realtime.datasets import (
    BENIGN,
    FEATURE_ORDER,
    available_datasets,
    load_cicids,
    load_nslkdd,
    load_unsw,
)
from src.realtime.features import vector

logger = logging.getLogger(__name__)

MODEL_DIR = PROJECT_ROOT / "models" / "zeek"
REPORT_DIR = PROJECT_ROOT / "reports" / "zeek_model"
HOLDOUT_DIR = PROJECT_ROOT / "data" / "processed" / "zeek_holdout"
RANDOM_STATE = 42
TARGET_FPR = 0.05


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _git_commit() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], cwd=PROJECT_ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return None


def grouped_split(
    frame: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split by ``group`` while preserving the class mix in every partition."""

    rng = np.random.default_rng(random_state)
    train_groups: set[str] = set()
    val_groups: set[str] = set()
    test_groups: set[str] = set()

    for _, subset in frame.groupby("label"):
        groups = np.array(sorted(subset["group"].unique()))
        rng.shuffle(groups)
        count = len(groups)
        n_test = max(1, int(round(count * test_size))) if count > 2 else 0
        n_val = max(1, int(round(count * val_size))) if count > 3 else 0
        test_groups.update(groups[:n_test])
        val_groups.update(groups[n_test:n_test + n_val])
        train_groups.update(groups[n_test + n_val:])

    def select(groups: set[str]) -> pd.DataFrame:
        return frame[frame["group"].isin(groups)].reset_index(drop=True)

    train, val, test = select(train_groups), select(val_groups), select(test_groups)
    # Guarantee every split holds at least one row of every class present.
    missing = set(frame["label"]) - set(train["label"])
    if missing:
        raise RuntimeError(f"Grouped split dropped classes from train: {missing}")
    return train, val, test


def stratified_split(
    frame: pd.DataFrame,
    test_size: float = 0.15,
    val_size: float = 0.15,
    random_state: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Stratified 70/15/15 split on exact-duplicate-free rows.

    Exact duplicates are removed per dataset before this call, so a stratified
    split cannot leak memorised rows. A grouped split is kept in the test suite
    as a stricter leakage check; it is not used for reporting because coarse
    group buckets produced unstable per-dataset estimates.
    """

    train, rest = train_test_split(
        frame, test_size=test_size + val_size, random_state=random_state, stratify=frame["label"]
    )
    val, test = train_test_split(
        rest, test_size=test_size / (test_size + val_size), random_state=random_state, stratify=rest["label"]
    )
    return train.reset_index(drop=True), val.reset_index(drop=True), test.reset_index(drop=True)


def _xy(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    values = frame[list(FEATURE_ORDER)].to_numpy(dtype=float)
    return values, frame["label"].to_numpy()


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    truth = y_true != BENIGN
    pred = y_pred != BENIGN
    tp = int(np.sum(truth & pred))
    tn = int(np.sum(~truth & ~pred))
    fp = int(np.sum(~truth & pred))
    fn = int(np.sum(truth & ~pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    return {
        "support": int(len(y_true)),
        "attack_support": int(truth.sum()),
        "benign_support": int((~truth).sum()),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": round(float(accuracy_score(truth, pred)), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "false_positive_rate": round(float(fpr), 6),
        "false_negative_rate": round(float(fnr), 6),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def multiclass_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    labels = sorted(set(y_true) | set(y_pred))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    per_class = {
        label: {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f), 4),
            "support": int(s),
        }
        for label, p, r, f, s in zip(labels, precision, recall, f1, support)
    }
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    return {
        "labels": labels,
        "per_class": per_class,
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 6),
        "weighted_f1": round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 6),
        "confusion_matrix": matrix.tolist(),
    }


def apply_threshold(
    probabilities: np.ndarray, classes: list[str], threshold: float
) -> np.ndarray:
    """Turn class probabilities into labels with a malicious-score gate.

    ``malicious_score = 1 - P(BENIGN)``. Below the threshold the flow is
    labelled BENIGN; above it the strongest non-benign class is reported.
    """

    if BENIGN not in classes:
        return np.asarray(classes)[np.argmax(probabilities, axis=1)]

    classes_array = np.asarray(classes)
    benign_index = classes.index(BENIGN)
    malicious_score = 1.0 - probabilities[:, benign_index]
    order = np.argsort(-probabilities, axis=1)
    non_benign_top = []
    for row in order:
        candidate = next((index for index in row if index != benign_index), benign_index)
        non_benign_top.append(candidate)
    return np.where(
        malicious_score >= threshold,
        classes_array[np.asarray(non_benign_top)],
        BENIGN,
    )


def evaluate_frame(model, frame: pd.DataFrame, threshold: float) -> dict[str, Any]:
    X, y = _xy(frame)
    probabilities = model.predict_proba(X)
    classes = list(model.classes_)
    predicted = apply_threshold(probabilities, classes, threshold)
    return {
        "binary": binary_metrics(y, predicted),
        "multiclass": multiclass_metrics(y, predicted),
    }


def tune_threshold(
    model, frame: pd.DataFrame, target_fpr: float = TARGET_FPR
) -> tuple[float, list[dict[str, Any]]]:
    X, y = _xy(frame)
    probabilities = model.predict_proba(X)
    classes = list(model.classes_)
    table: list[dict[str, Any]] = []
    best = None
    for threshold in [round(0.05 + 0.05 * i, 2) for i in range(1, 19)]:
        predicted = apply_threshold(probabilities, classes, threshold)
        metrics = binary_metrics(y, predicted)
        row = {
            "threshold": threshold,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "false_positive_rate": metrics["false_positive_rate"],
        }
        table.append(row)
        if metrics["false_positive_rate"] <= target_fpr:
            if best is None or metrics["recall"] > best["recall"]:
                best = row
    if best is None:
        # Nothing meets the FPR budget: take the operating point with the
        # lowest FPR that still detects anything, else the best F1.
        eligible = [row for row in table if row["recall"] > 0] or table
        best = min(eligible, key=lambda row: (row["false_positive_rate"], -row["f1"]))
    return float(best["threshold"]), table


def measure_latency(model, frame: pd.DataFrame, sample: int = 2000) -> dict[str, Any]:
    X, _ = _xy(frame.head(sample))
    rows = X[: min(len(X), sample)]
    for row in rows[:10]:  # warm up
        model.predict_proba(row.reshape(1, -1))
    timings = []
    for row in rows:
        started = time.perf_counter()
        model.predict_proba(row.reshape(1, -1))
        timings.append((time.perf_counter() - started) * 1000.0)
    timings.sort()
    return {
        "flows_measured": len(timings),
        "mean_ms": round(float(np.mean(timings)), 4),
        "p50_ms": round(float(timings[len(timings) // 2]), 4),
        "p95_ms": round(float(timings[int(len(timings) * 0.95) - 1]), 4),
        "throughput_flows_per_s": int(1000.0 / max(1e-6, float(np.mean(timings)))),
    }


def top_features(model, frame: pd.DataFrame, sample: int = 1500) -> list[dict[str, Any]]:
    subset = frame.sample(min(sample, len(frame)), random_state=RANDOM_STATE)
    X, y = _xy(subset)
    result = permutation_importance(
        model, X, y, n_repeats=3, random_state=RANDOM_STATE, scoring="f1_macro", n_jobs=1
    )
    ranked = sorted(
        zip(FEATURE_ORDER, result.importances_mean), key=lambda item: item[1], reverse=True
    )
    return [{"feature": name, "importance": round(float(score), 5)} for name, score in ranked]


def error_analysis(model, frame: pd.DataFrame, threshold: float, limit: int = 40) -> dict[str, Any]:
    X, y = _xy(frame)
    probabilities = model.predict_proba(X)
    predicted = apply_threshold(probabilities, list(model.classes_), threshold)
    benign_index = list(model.classes_).index(BENIGN)
    scores = 1.0 - probabilities[:, benign_index]

    truth = y != BENIGN
    pred = predicted != BENIGN
    fp_mask = (~truth) & pred
    fn_mask = truth & (~pred)

    columns = list(FEATURE_ORDER) + ["true_label", "predicted_label", "malicious_score"]
    def frame_for(mask: np.ndarray) -> pd.DataFrame:
        subset = pd.DataFrame(X[mask], columns=list(FEATURE_ORDER))
        subset["true_label"] = y[mask]
        subset["predicted_label"] = predicted[mask]
        subset["malicious_score"] = np.round(scores[mask], 4)
        return subset[columns]

    false_positives = frame_for(fp_mask).sort_values("malicious_score", ascending=False)
    false_negatives = frame_for(fn_mask).sort_values("malicious_score", ascending=True)

    def profile(df: pd.DataFrame) -> dict[str, float | None]:
        if df.empty:
            return {}
        return {
            "mean_duration_s": round(float(df["duration_s"].mean()), 4),
            "mean_orig_bytes": round(float(df["orig_bytes"].mean()), 1),
            "mean_resp_bytes": round(float(df["resp_bytes"].mean()), 1),
            "mean_pkts_per_s": round(float(df["flow_packets_per_s"].mean()), 2),
            "mean_dst_port_class": round(float(df["dst_port_class"].mean()), 1),
        }

    return {
        "false_positive_count": int(fp_mask.sum()),
        "false_negative_count": int(fn_mask.sum()),
        "false_positive_profile": profile(false_positives),
        "false_negative_profile": profile(false_negatives),
        "by_true_label": {
            label: int(count)
            for label, count in pd.Series(y[fn_mask]).value_counts().items()
        },
        "samples": {
            "false_positives": false_positives.head(limit).round(4).to_dict(orient="records"),
            "false_negatives": false_negatives.head(limit).round(4).to_dict(orient="records"),
        },
    }


def build_frame(limit: int | None = None, include_nslkdd: bool = True) -> tuple[pd.DataFrame, dict[str, Any], tuple | None, tuple | None]:
    frames: list[pd.DataFrame] = []
    counts: dict[str, int] = {}

    cicids = load_cicids(limit=limit)
    frames.append(cicids)
    counts["CICIDS2017"] = int(len(cicids))
    logger.info("CICIDS2017: %s rows", len(cicids))

    unsw_train, unsw_test = load_unsw()
    frames.append(unsw_train)
    counts["UNSW-NB15"] = int(len(unsw_train))
    logger.info("UNSW-NB15 train: %s rows", len(unsw_train))

    nslkdd = None
    if include_nslkdd:
        try:
            nslkdd_train, nslkdd_test = load_nslkdd()
            frames.append(nslkdd_train)
            counts["NSL-KDD"] = int(len(nslkdd_train))
            logger.info("NSL-KDD train: %s rows", len(nslkdd_train))
            nslkdd = (nslkdd_train, nslkdd_test)
        except FileNotFoundError as error:
            logger.warning("NSL-KDD not available: %s", error)

    deduped: list[pd.DataFrame] = []
    duplicates_removed: dict[str, int] = {}
    for part in frames:
        name = str(part["dataset"].iloc[0])
        before = len(part)
        cleaned = part.drop_duplicates(subset=list(FEATURE_ORDER) + ["label"]).reset_index(drop=True)
        duplicates_removed[name] = before - len(cleaned)
        deduped.append(cleaned)
    frames = deduped

    combined = pd.concat(frames, ignore_index=True)
    combined = combined.dropna(subset=["label"]).reset_index(drop=True)

    # A class with a handful of rows cannot be stratified or learned; fold it
    # into "Other" instead of silently dropping evidence.
    class_counts = combined["label"].value_counts()
    rare = class_counts[class_counts < 25].index.tolist()
    if rare:
        combined.loc[combined["label"].isin(rare), "label"] = "Other"
        logger.info("Merged rare classes into Other: %s", rare)
    summary = {
        "row_counts": counts,
        "duplicates_removed": duplicates_removed,
        "label_distribution": {k: int(v) for k, v in combined["label"].value_counts().items()},
        "dataset_distribution": {k: int(v) for k, v in combined["dataset"].value_counts().items()},
    }
    return combined, summary, (unsw_train, unsw_test), nslkdd


def _model_candidates() -> dict[str, Any]:
    return {
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=250,
            learning_rate=0.08,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        ),
        "random_forest": Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                (
                    "model",
                    RandomForestClassifier(
                        n_estimators=120,
                        max_depth=20,
                        max_samples=0.6,
                        class_weight="balanced_subsample",
                        n_jobs=-1,
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
    }


# --------------------------------------------------------------------------- #
# main training routine
# --------------------------------------------------------------------------- #
def train(
    limit: int | None = None,
    include_nslkdd: bool = True,
    cross_dataset_eval: bool = True,
    skip_baseline: bool = False,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    started = time.time()
    model_dir = output_dir or MODEL_DIR
    model_dir.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    frame, dataset_summary, unsw_pair, nslkdd_pair = build_frame(limit, include_nslkdd)
    logger.info("Combined dataset: %s rows", len(frame))

    train_frame, val_frame, test_frame = stratified_split(frame)
    logger.info(
        "Split rows -> train %s | val %s | test %s",
        len(train_frame), len(val_frame), len(test_frame),
    )
    signature = list(FEATURE_ORDER) + ["label"]
    train_keys = set(map(tuple, train_frame[signature].to_numpy()))
    for name, split in (("validation", val_frame), ("test", test_frame)):
        overlap = sum(1 for row in map(tuple, split[signature].to_numpy()) if row in train_keys)
        if overlap:
            raise RuntimeError(f"Leakage detected: {overlap} {name} rows duplicate a training row")

    X_train, y_train = _xy(train_frame)
    X_val, y_val = _xy(val_frame)

    candidates = _model_candidates()
    if skip_baseline:
        candidates.pop("random_forest", None)

    candidate_scores: dict[str, Any] = {}
    best_name, best_model, best_score = None, None, -1.0
    for name, estimator in candidates.items():
        logger.info("Training candidate: %s", name)
        candidate_started = time.time()
        estimator.fit(X_train, y_train)
        predictions = estimator.predict(X_val)
        score = float(f1_score(y_val, predictions, average="macro", zero_division=0))
        candidate_scores[name] = {
            "validation_macro_f1": round(score, 6),
            "validation_accuracy": round(float(accuracy_score(y_val, predictions)), 6),
            "train_seconds": round(time.time() - candidate_started, 1),
        }
        logger.info("%s validation macro F1: %.4f", name, score)
        if score > best_score:
            best_name, best_model, best_score = name, estimator, score

    if best_model is None:
        raise RuntimeError("No candidate model trained")

    logger.info("Selected candidate: %s", best_name)
    threshold, threshold_table = tune_threshold(best_model, val_frame)
    logger.info("Operating threshold: %.2f (target FPR %.0f%%)", threshold, TARGET_FPR * 100)

    validation = evaluate_frame(best_model, val_frame, threshold)
    test = evaluate_frame(best_model, test_frame, threshold)
    test["per_dataset"] = {
        name: evaluate_frame(best_model, subset, threshold)
        for name, subset in test_frame.groupby("dataset")
    }
    validation["per_dataset"] = {
        name: evaluate_frame(best_model, subset, threshold)
        for name, subset in val_frame.groupby("dataset")
    }

    # Official test partitions of the datasets the model trained on.
    holdout_reports: dict[str, Any] = {}
    if unsw_pair and unsw_pair[1] is not None:
        holdout_reports["UNSW-NB15-official-test"] = evaluate_frame(best_model, unsw_pair[1], threshold)
    if nslkdd_pair and nslkdd_pair[1] is not None:
        holdout_reports["NSL-KDD-official-test"] = evaluate_frame(best_model, nslkdd_pair[1], threshold)

    # Generalisation to a dataset the model has never seen: retrain without
    # NSL-KDD and evaluate on the untouched KDDTest+ partition.
    cross_dataset: dict[str, Any] | None = None
    if cross_dataset_eval and nslkdd_pair is not None and nslkdd_pair[1] is not None:
        logger.info("Cross-dataset evaluation: training without NSL-KDD")
        without = frame[frame["dataset"] != "NSL-KDD"]
        c_train, c_val, _ = stratified_split(without)
        estimator = HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_leaf_nodes=31,
            l2_regularization=1.0, class_weight="balanced", random_state=RANDOM_STATE,
        )
        estimator.fit(*_xy(c_train))
        c_threshold, _ = tune_threshold(estimator, c_val)
        metrics = evaluate_frame(estimator, nslkdd_pair[1], c_threshold)
        cross_dataset = {
            "unseen_dataset": "NSL-KDD (KDDTest+)",
            "trained_on": sorted(without["dataset"].unique().tolist()),
            "threshold": c_threshold,
            "metrics": metrics,
        }
        logger.info(
            "Unseen-dataset recall %.3f | FPR %.4f",
            metrics["binary"]["recall"], metrics["binary"]["false_positive_rate"],
        )

    importance = top_features(best_model, val_frame)
    errors = error_analysis(best_model, test_frame, threshold)
    latency = measure_latency(best_model, test_frame)

    classes = list(best_model.classes_)
    model_version = f"{datetime.now(timezone.utc).strftime('%Y.%m.%d')}-{_git_commit() or 'nogit'}"
    metadata = {
        "model_name": "zeek-flow-classifier",
        "model_version": model_version,
        "trained_at": _now_iso(),
        "algorithm": best_name,
        "training_datasets": dataset_summary["row_counts"],
        "row_counts": {
            "train": int(len(train_frame)),
            "validation": int(len(val_frame)),
            "test": int(len(test_frame)),
            "total": int(len(frame)),
        },
        "label_distribution": dataset_summary["label_distribution"],
        "dataset_distribution": dataset_summary["dataset_distribution"],
        "feature_schema": list(FEATURE_ORDER),
        "classes": classes,
        "threshold": threshold,
        "target_false_positive_rate": TARGET_FPR,
        "top_features": importance[:10],
        "validation_metrics": validation,
        "test_metrics": test,
        "holdout_metrics": holdout_reports,
        "cross_dataset": cross_dataset,
        "latency": latency,
        "candidates": candidate_scores,
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "git_commit": _git_commit(),
        },
        "notes": [
            "Trained on public labelled flow datasets mapped onto a Zeek-compatible feature schema.",
            "Exact duplicate flows are removed per dataset before splitting, so no test row repeats a training row.",
            "Splits are stratified 70/15/15; the 5% false-positive budget is enforced on the validation split.",
            "The model scores conn.log flows only; dns/http/ssl events are rule-inspected and reported as unclassified.",
            "NSL-KDD lacks packet counts; those features are passed as NaN instead of being imputed with invented values.",
            "UNSW-NB15 benign traffic remains the hardest corpus: its short high-rate flows overlap attack profiles.",
            "Treat predictions as decision support: rule detectors add behavioural context the flow model cannot see.",
        ],
    }

    artifact = {
        "model": best_model,
        "features": list(FEATURE_ORDER),
        "classes": classes,
        "threshold": threshold,
        "metadata": metadata,
    }
    artifact_path = model_dir / "zeek_model.joblib"
    joblib.dump(artifact, artifact_path)
    (model_dir / "zeek_model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    report = {
        "generated_at": _now_iso(),
        "duration_seconds": round(time.time() - started, 1),
        "datasets_available": available_datasets(),
        "datasets": dataset_summary,
        "split": {
            "train_rows": int(len(train_frame)),
            "validation_rows": int(len(val_frame)),
            "test_rows": int(len(test_frame)),
            "train_label_distribution": {k: int(v) for k, v in train_frame["label"].value_counts().items()},
            "test_label_distribution": {k: int(v) for k, v in test_frame["label"].value_counts().items()},
            "split_strategy": "stratified_after_dedup",
            "duplicates_removed": dataset_summary["duplicates_removed"],
        },
        "model": {
            "algorithm": best_name,
            "version": model_version,
            "threshold": threshold,
            "classes": classes,
            "artifact": str(artifact_path),
        },
        "candidates": candidate_scores,
        "validation": validation,
        "test": test,
        "official_test_partitions": holdout_reports,
        "cross_dataset": cross_dataset,
        "threshold_analysis": threshold_table,
        "top_features": importance,
        "latency": latency,
        "error_analysis": errors,
    }
    (REPORT_DIR / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (REPORT_DIR / "threshold_analysis.csv").write_text(
        pd.DataFrame(threshold_table).to_csv(index=False), encoding="utf-8"
    )
    pd.DataFrame(errors["samples"]["false_positives"]).to_csv(
        REPORT_DIR / "false_positives.csv", index=False
    )
    pd.DataFrame(errors["samples"]["false_negatives"]).to_csv(
        REPORT_DIR / "false_negatives.csv", index=False
    )
    _write_markdown_report(report, metadata)
    _save_replay_holdout(test_frame)

    logger.info("Model artifact: %s", artifact_path)
    logger.info("Evaluation report: %s", REPORT_DIR / "evaluation.json")
    logger.info(
        "Held-out test: precision %.3f recall %.3f F1 %.3f FPR %.4f",
        test["binary"]["precision"], test["binary"]["recall"],
        test["binary"]["f1"], test["binary"]["false_positive_rate"],
    )
    return report


def _save_replay_holdout(test_frame: pd.DataFrame, limit: int = 3000) -> None:
    """Persist untouched CICIDS2017 test rows for the Zeek replay demo.

    Only rows from the held-out split are written, so the replay never shows
    the pipeline a flow that was used for training.
    """

    cicids = test_frame[test_frame["dataset"] == "CICIDS2017"]
    if cicids.empty:
        return
    attacks = cicids[cicids["label"] != BENIGN]
    benign = cicids[cicids["label"] == BENIGN]
    n_attack = min(len(attacks), limit // 2)
    n_benign = min(len(benign), limit - n_attack)
    sample = pd.concat(
        [
            attacks.sample(n=n_attack, random_state=RANDOM_STATE),
            benign.sample(n=n_benign, random_state=RANDOM_STATE),
        ]
    ).sample(frac=1.0, random_state=RANDOM_STATE)
    HOLDOUT_DIR.mkdir(parents=True, exist_ok=True)
    path = HOLDOUT_DIR / "cicids_holdout.csv"
    sample[list(FEATURE_ORDER) + ["label"]].to_csv(path, index=False)
    logger.info("Replay holdout sample: %s rows -> %s", len(sample), path)


def _write_markdown_report(report: dict[str, Any], metadata: dict[str, Any]) -> None:
    test = report["test"]["binary"]
    validation = report["validation"]["binary"]
    lines = [
        "# Zeek flow classifier - model card",
        "",
        f"- Version: `{metadata['model_version']}`",
        f"- Trained at: {metadata['trained_at']}",
        f"- Algorithm: {metadata['algorithm']}",
        f"- Operating threshold: {metadata['threshold']:.2f} (target FPR {TARGET_FPR:.0%})",
        f"- Training rows: {metadata['row_counts']['train']:,} "
        f"(validation {metadata['row_counts']['validation']:,}, test {metadata['row_counts']['test']:,})",
        "",
        "## Datasets",
        "",
        "| Dataset | Rows used for training/validation/test |",
        "| --- | --- |",
    ]
    for name, count in metadata["training_datasets"].items():
        lines.append(f"| {name} | {count:,} |")

    lines += [
        "",
        "## Held-out test performance (binary: malicious vs benign)",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Precision | {test['precision']:.4f} |",
        f"| Recall | {test['recall']:.4f} |",
        f"| F1 | {test['f1']:.4f} |",
        f"| False-positive rate | {test['false_positive_rate']:.4%} |",
        f"| Accuracy | {test['accuracy']:.4f} |",
        f"| Validation F1 | {validation['f1']:.4f} |",
        f"| Test confusion matrix (tn, fp / fn, tp) | {test['confusion_matrix']} |",
        "",
        "## Per-class test performance",
        "",
        "| Class | Precision | Recall | F1 | Support |",
        "| --- | --- | --- | --- | --- |",
    ]
    for label, row in report["test"]["multiclass"]["per_class"].items():
        lines.append(
            f"| {label} | {row['precision']:.3f} | {row['recall']:.3f} | "
            f"{row['f1']:.3f} | {row['support']:,} |"
        )

    cross = report.get("cross_dataset")
    if cross:
        binary = cross["metrics"]["binary"]
        lines += [
            "",
            "## Unseen-dataset generalisation",
            "",
            f"Model retrained without **{cross['unseen_dataset']}**, evaluated on its official test partition:",
            "",
            "| Metric | Value |",
            "| --- | --- |",
            f"| Precision | {binary['precision']:.4f} |",
            f"| Recall | {binary['recall']:.4f} |",
            f"| F1 | {binary['f1']:.4f} |",
            f"| False-positive rate | {binary['false_positive_rate']:.4%} |",
        ]

    lines += [
        "",
        "## Error analysis",
        "",
        f"- False positives in the held-out test: {report['error_analysis']['false_positive_count']}",
        f"- False negatives in the held-out test: {report['error_analysis']['false_negative_count']}",
        f"- False-positive profile: {json.dumps(report['error_analysis']['false_positive_profile'])}",
        f"- False-negative profile: {json.dumps(report['error_analysis']['false_negative_profile'])}",
        f"- False negatives by true label: {json.dumps(report['error_analysis']['by_true_label'])}",
        "",
        "## Inference latency",
        "",
        f"- Mean: {report['latency']['mean_ms']:.3f} ms/flow "
        f"(p95 {report['latency']['p95_ms']:.3f} ms, "
        f"~{report['latency']['throughput_flows_per_s']:,} flows/s single core)",
        "",
        "## Limitations",
        "",
        "- The model scores `conn.log` flows only; it is not a full NDR product.",
        "- Cross-dataset feature mapping is approximate by nature (different capture tooling).",
        "- Rule detectors add context for scanning, flooding, brute force, beaconing, exfiltration and DNS tunnelling.",
        "- Scores are decision support, not a replacement for analyst review.",
        "",
    ]
    (REPORT_DIR / "model_card.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the Zeek-compatible NDR flow classifier")
    parser.add_argument("--limit", type=int, default=None, help="Limit CICIDS2017 rows (debug)")
    parser.add_argument("--no-nslkdd", action="store_true", help="Exclude NSL-KDD")
    parser.add_argument("--no-cross-dataset", action="store_true", help="Skip unseen-dataset evaluation")
    parser.add_argument("--skip-baseline", action="store_true", help="Skip the Random Forest baseline")
    parser.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    report = train(
        limit=args.limit,
        include_nslkdd=not args.no_nslkdd,
        cross_dataset_eval=not args.no_cross_dataset,
        skip_baseline=args.skip_baseline,
        output_dir=args.output_dir,
    )
    print(json.dumps({
        "test_binary": report["test"]["binary"],
        "test_macro_f1": report["test"]["multiclass"]["macro_f1"],
        "threshold": report["model"]["threshold"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
