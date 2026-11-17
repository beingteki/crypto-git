#!/usr/bin/env python3
"""Create assignment summary tables and plots from untouched raw.csv files."""
import csv
import statistics
from pathlib import Path
from collections import defaultdict

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
RUNS = [("run-1", ROOT / "results" / "run-1" / "raw.csv"),
        ("run-2", ROOT / "results" / "run-2" / "raw.csv")]
GRAPHS = ROOT / "graphs"
REPORTS = ROOT / "reports"
GRAPHS.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)


def read_data(path):
    if not path.exists():
        raise SystemExit(f"Missing {path}. Run my_project.py in both environments first.")
    grouped = defaultdict(list)
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            # Exclude run 0 warm-up exactly as specified in the assignment.
            if int(row["run"]) == 0:
                continue
            key = (row["part"], row["algorithm"], row["operation"], int(row["message_bytes"]))
            grouped[key].append(int(row["nanoseconds"]) / 1_000_000)
    return grouped


def stats(values):
    qs = statistics.quantiles(values, n=4, method="exclusive")
    return statistics.median(values), qs[2] - qs[0]


def make_table(grouped, run_name, part, operations, filename):
    rows = []
    for (p, alg, op, msg), values in sorted(grouped.items()):
        if p != part:
            continue
        med, iqr = stats(values)
        rows.append({"algorithm": alg, "message_bytes": msg, "operation": op,
                     "median_ms": med, "iqr_ms": iqr})
    out = REPORTS / f"{run_name}_{filename}.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["algorithm", "message_bytes", "operation",
                                          "median_ms", "iqr_ms"])
        w.writeheader()
        w.writerows(rows)
    return rows


def plot_grouped_bars(rows, run_name, part, operations, filename, title):
    algs = list(dict.fromkeys(r["algorithm"] for r in rows))
    x = list(range(len(algs)))
    width = 0.8 / len(operations)
    fig, ax = plt.subplots(figsize=(max(11, len(algs) * 1.35), 6))
    for i, op in enumerate(operations):
        medians = []
        for alg in algs:
            vals = [r["median_ms"] for r in rows if r["algorithm"] == alg and r["operation"] == op]
            medians.append(vals[0] if vals else float("nan"))
        ax.bar([v - 0.4 + width/2 + i*width for v in x], medians,
               width=width, label=op)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(algs, rotation=25, ha="right")
    ax.set_ylabel("Median time (ms)")
    ax.set_xlabel("Algorithm")
    ax.set_title(title)
    ax.legend()
    ax.grid(axis="y", which="both", alpha=0.25)
    fig.tight_layout()
    fig.savefig(GRAPHS / f"{run_name}_{filename}.png", dpi=200)
    plt.close(fig)


def plot_aead(rows, run_name):
    algs = list(dict.fromkeys(r["algorithm"] for r in rows))
    fig, ax = plt.subplots(figsize=(9, 6))
    for alg in algs:
        vals = sorted([r for r in rows if r["algorithm"] == alg and r["operation"] == "encrypt"],
                      key=lambda r: r["message_bytes"])
        ax.plot([r["message_bytes"] for r in vals], [r["median_ms"] for r in vals],
                marker="o", label=alg)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Message length (bytes)")
    ax.set_ylabel("Median encryption time (ms)")
    ax.set_title(f"Authenticated encryption — {run_name}")
    ax.legend()
    ax.grid(which="both", alpha=0.25)
    fig.tight_layout()
    fig.savefig(GRAPHS / f"{run_name}_authenticated_encryption.png", dpi=200)
    plt.close(fig)


for run_name, csv_path in RUNS:
    data = read_data(csv_path)
    kem = make_table(data, run_name, "kem", ["keygen", "encapsulate", "decapsulate"],
                     "key_establishment")
    sig = make_table(data, run_name, "signature", ["keygen", "sign", "verify"],
                     "digital_signatures")
    aead = make_table(data, run_name, "aead", ["encrypt", "decrypt"],
                      "authenticated_encryption")
    plot_grouped_bars(kem, run_name, "kem", ["keygen", "encapsulate", "decapsulate"],
                      "key_establishment", f"Key establishment — {run_name}")
    plot_grouped_bars(sig, run_name, "signature", ["keygen", "sign", "verify"],
                      "digital_signatures", f"Digital signatures — {run_name}")
    plot_aead(aead, run_name)

print("Created six summary tables in reports/ and six plots in graphs/.")
