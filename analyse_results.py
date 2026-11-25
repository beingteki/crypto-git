#!/usr/bin/env python3
"""Generate all CryptoBench summary tables and assignment-format plots.

The original raw CSV files are read-only inputs. Run 0 is retained in those
files and excluded from descriptive statistics. Quartiles use the default
exclusive method of statistics.quantiles(values, n=4).
"""
from __future__ import annotations

import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
TABLES = ROOT / "tables"
GRAPHS = ROOT / "graphs"

ENVIRONMENTS = [
    {
        "key": "environment_1",
        "label": "Environment 1 - MacBook Pro M3 Pro (macOS ARM64)",
        "raw": ROOT / "results" / "run-1" / "raw.csv",
    },
    {
        "key": "environment_2",
        "label": "Environment 2 - Kali Linux VM (x86_64)",
        "raw": ROOT / "results" / "run-2" / "raw.csv",
    },
]

COLUMNS = ["part", "algorithm", "operation", "message_bytes", "run", "nanoseconds"]
KEM_ORDER = [
    "RSA-OAEP-3072", "RSA-OAEP-7680",
    "ECDH-P-256", "ECDH-P-384", "ECDH-P-521", "X25519",
    "ML-KEM-768", "ML-KEM-1024",
]
SIGNATURE_ORDER = [
    "RSA-PSS-3072", "RSA-PSS-7680",
    "ECDSA-P-256", "ECDSA-P-384", "ECDSA-P-521", "Ed25519",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
]
AEAD_ORDER = ["AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-GCM-SIV"]
KEM_OPS = ["keygen", "encapsulate", "decapsulate"]
SIGNATURE_OPS = ["keygen", "sign", "verify"]
AEAD_OPS = ["encrypt", "decrypt"]
MESSAGE_SIZES = [64, 1024, 16384, 1048576]


def load_raw(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"Raw dataset not found: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != COLUMNS:
            raise ValueError(f"Unexpected CSV columns in {path}: {reader.fieldnames}")
        rows = []
        for row in reader:
            rows.append({
                "part": row["part"],
                "algorithm": row["algorithm"],
                "operation": row["operation"],
                "message_bytes": int(row["message_bytes"]),
                "run": int(row["run"]),
                "nanoseconds": int(row["nanoseconds"]),
            })
    if not rows:
        raise ValueError(f"No measurements found in {path}")
    if any(r["nanoseconds"] <= 0 for r in rows):
        raise ValueError(f"Non-positive timing found in {path}")
    return rows


def validate(rows: list[dict[str, Any]], env_key: str) -> dict[str, Any]:
    grouped: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (row["part"], row["algorithm"], row["operation"], row["message_bytes"])
        grouped[key].append(row)
    sizes = [len(v) for v in grouped.values()]
    warmup_groups = sum(sum(r["run"] == 0 for r in group) == 1 for group in grouped.values())
    bad_run_groups = []
    for key, group in grouped.items():
        runs = [r["run"] for r in group]
        expected = 21 if key[0] in {"kem", "signature"} and key[1].startswith("RSA-") and key[2] == "keygen" else 101
        if (len(group) != expected or runs.count(0) != 1
                or len(set(runs)) != len(runs) or set(runs) != set(range(expected))):
            bad_run_groups.append((key, len(group), runs.count(0), expected))
    if bad_run_groups:
        raise ValueError(f"Run count/warm-up validation failed: {bad_run_groups[:5]}")
    expected_groups = {
        ("kem", algorithm, operation, 0)
        for algorithm in KEM_ORDER for operation in KEM_OPS
    } | {
        ("signature", algorithm, operation, 0)
        for algorithm in SIGNATURE_ORDER for operation in SIGNATURE_OPS
    } | {
        ("aead", algorithm, operation, size)
        for algorithm in AEAD_ORDER for operation in AEAD_OPS for size in MESSAGE_SIZES
    }
    actual_groups = set(grouped)
    if actual_groups != expected_groups:
        raise ValueError(
            f"Unexpected groups for {env_key}: "
            f"missing {sorted(expected_groups - actual_groups)}, "
            f"extra {sorted(actual_groups - expected_groups)}"
        )
    return {
        "environment": env_key,
        "raw_rows": len(rows),
        "operation_groups": len(grouped),
        "groups_with_101_rows_including_warmup": sizes.count(101),
        "groups_with_21_rows_including_warmup": sizes.count(21),
        "warmup_rows": warmup_groups,
        "analysis_runs_per_normal_group": 100,
        "analysis_runs_per_rsa_keygen_group": 20,
        "missing_cells": 0,
        "validation": "PASS",
    }


def calculate_stats(rows: list[dict[str, Any]]) -> dict[tuple, dict[str, float | int]]:
    grouped: dict[tuple, list[int]] = defaultdict(list)
    for row in rows:
        if row["run"] == 0:
            continue
        key = (row["part"], row["algorithm"], row["operation"], row["message_bytes"])
        grouped[key].append(row["nanoseconds"])
    result = {}
    for key, ns_values in grouped.items():
        quartiles = statistics.quantiles(ns_values, n=4)  # default exclusive method
        median_ns = statistics.median(ns_values)
        q1_ns, q3_ns = quartiles[0], quartiles[2]
        result[key] = {
            "n": len(ns_values),
            "median_ms": median_ns / 1_000_000,
            "q1_ms": q1_ns / 1_000_000,
            "q3_ms": q3_ns / 1_000_000,
            "iqr_ms": (q3_ns - q1_ns) / 1_000_000,
        }
    return result


def sigfig(value: float, digits: int = 3) -> str:
    """Format to significant figures without scientific notation."""
    if value == 0:
        return "0"
    exponent = math.floor(math.log10(abs(value)))
    decimals = digits - 1 - exponent
    rounded = round(value, decimals)
    if decimals > 0:
        return f"{rounded:.{decimals}f}"
    return f"{rounded:.0f}"


def ordered_present(order: list[str], stats: dict, part: str) -> list[str]:
    present = {key[1] for key in stats if key[0] == part}
    return [name for name in order if name in present] + sorted(present - set(order))


def write_csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def table_kem_or_signature(stats: dict, env_key: str, part: str, order: list[str], ops: list[str]) -> None:
    header = ["Algorithm"]
    for op in ops:
        header += [f"{op} median (ms)", f"{op} IQR (ms)"]
    rows = []
    for alg in ordered_present(order, stats, part):
        row: list[Any] = [alg]
        for op in ops:
            key = (part, alg, op, 0)
            s = stats[key]
            row += [sigfig(float(s["median_ms"])), sigfig(float(s["iqr_ms"]))]
        rows.append(row)
    write_csv(TABLES / f"{env_key}_{part}.csv", header, rows)


def table_aead(stats: dict, env_key: str) -> None:
    header = ["Algorithm", "Message bytes", "Encrypt median (ms)", "Encrypt IQR (ms)",
              "Decrypt median (ms)", "Decrypt IQR (ms)"]
    rows = []
    for alg in ordered_present(AEAD_ORDER, stats, "aead"):
        for size in MESSAGE_SIZES:
            enc = stats[("aead", alg, "encrypt", size)]
            dec = stats[("aead", alg, "decrypt", size)]
            rows.append([alg, size, sigfig(float(enc["median_ms"])), sigfig(float(enc["iqr_ms"])),
                         sigfig(float(dec["median_ms"])), sigfig(float(dec["iqr_ms"]))])
    write_csv(TABLES / f"{env_key}_aead.csv", header, rows)


def plot_grouped(stats: dict, env: dict, part: str, order: list[str], ops: list[str], title: str) -> None:
    algorithms = ordered_present(order, stats, part)
    positions = list(range(len(algorithms)))
    width = 0.78 / len(ops)
    fig, ax = plt.subplots(figsize=(max(12, 1.35 * len(algorithms)), 6.6))
    for op_index, op in enumerate(ops):
        medians, lower, upper = [], [], []
        for alg in algorithms:
            s = stats[(part, alg, op, 0)]
            med = float(s["median_ms"])
            medians.append(med)
            lower.append(max(med - float(s["q1_ms"]), 0.0))
            upper.append(max(float(s["q3_ms"]) - med, 0.0))
        offsets = [p - 0.39 + width / 2 + op_index * width for p in positions]
        ax.bar(offsets, medians, width=width, label=op, yerr=[lower, upper], capsize=2)
    ax.set_yscale("log")
    ax.set_xticks(positions)
    ax.set_xticklabels(algorithms, rotation=25, ha="right")
    ax.set_xlabel("Algorithm and parameter set")
    ax.set_ylabel("Median elapsed time (milliseconds; log scale)")
    ax.set_title(title, pad=14, fontsize=12)
    ax.grid(axis="y", which="both", alpha=0.25)
    ax.legend(title="Operation")
    fig.tight_layout()
    fig.savefig(GRAPHS / f"{env['key']}_{part}.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


def plot_aead(stats: dict, env: dict) -> None:
    fig, ax = plt.subplots(figsize=(9.5, 6.5))
    for alg in ordered_present(AEAD_ORDER, stats, "aead"):
        medians = [float(stats[("aead", alg, "encrypt", size)]["median_ms"]) for size in MESSAGE_SIZES]
        ax.plot(MESSAGE_SIZES, medians, marker="o", linewidth=1.8, label=alg)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Plaintext message length (bytes; log scale)")
    ax.set_ylabel("Median encryption elapsed time (milliseconds; log scale)")
    ax.set_title(f"Authenticated Encryption: Encryption Latency - {env['label']}", pad=12)
    ax.grid(True, which="both", alpha=0.25)
    ax.legend(title="AEAD algorithm")
    fig.tight_layout()
    fig.savefig(GRAPHS / f"{env['key']}_aead.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


def write_environment_ratios(all_stats: dict[str, dict]) -> None:
    left = all_stats["environment_1"]
    right = all_stats["environment_2"]
    header = ["Part", "Algorithm", "Operation", "Message bytes",
              "Environment 1 median (ms)", "Environment 2 median (ms)",
              "Environment 2 / Environment 1", "Relative change (%)", "Interpretation"]
    rows = []
    part_order = {"kem": 0, "signature": 1, "aead": 2}
    algorithm_order = {name: index for index, name in enumerate(
        KEM_ORDER + SIGNATURE_ORDER + AEAD_ORDER
    )}
    op_order = {
        "keygen": 0, "encapsulate": 1, "decapsulate": 2,
        "sign": 1, "verify": 2, "encrypt": 1, "decrypt": 2,
    }
    for key in sorted(left, key=lambda k: (
        part_order.get(k[0], 99), algorithm_order.get(k[1], 999),
        k[3], op_order.get(k[2], 99)
    )):
        if key not in right:
            raise ValueError(f"Unmatched measurement between environments: {key}")
        m1 = float(left[key]["median_ms"])
        m2 = float(right[key]["median_ms"])
        ratio = m2 / m1
        direction = "Kali VM slower" if ratio > 1 else "Kali VM faster" if ratio < 1 else "Equal medians"
        message_bytes = key[3] if key[0] == "aead" else ""
        rows.append([key[0], key[1], key[2], message_bytes, sigfig(m1), sigfig(m2),
                     f"{ratio:.3f}", f"{(ratio - 1) * 100:+.1f}", direction])
    write_csv(TABLES / "environment_2_vs_environment_1_ratios.csv", header, rows)


def main() -> None:
    TABLES.mkdir(exist_ok=True)
    GRAPHS.mkdir(exist_ok=True)
    all_stats = {}
    validation_rows = []
    for env in ENVIRONMENTS:
        raw = load_raw(env["raw"])
        validation_rows.append(validate(raw, env["key"]))
        stats = calculate_stats(raw)
        all_stats[env["key"]] = stats
        table_kem_or_signature(stats, env["key"], "kem", KEM_ORDER, KEM_OPS)
        table_kem_or_signature(stats, env["key"], "signature", SIGNATURE_ORDER, SIGNATURE_OPS)
        table_aead(stats, env["key"])
        plot_grouped(stats, env, "kem", KEM_ORDER, KEM_OPS,
                     f"Key Establishment Performance - {env['label']}")
        plot_grouped(stats, env, "signature", SIGNATURE_ORDER, SIGNATURE_OPS,
                     f"Digital Signature Performance - {env['label']}")
        plot_aead(stats, env)
    write_environment_ratios(all_stats)
    write_csv(TABLES / "validation_summary.csv",
              list(validation_rows[0].keys()),
              [[row[k] for k in validation_rows[0]] for row in validation_rows])
    print("PASS: two source CSVs validated; 83 operation groups per environment.")
    print("Created 6 result tables, 6 plots, 1 cross-environment ratio table and validation summary.")
    print(f"Tables: {TABLES}")
    print(f"Graphs: {GRAPHS}")


if __name__ == "__main__":
    main()
