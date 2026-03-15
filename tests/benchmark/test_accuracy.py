"""Benchmark accuracy test: precision / recall / F1 quality gates.

Quality gates (enforced as pytest assertions):
    precision >= 80%
    recall    >= 70%
"""
from __future__ import annotations

import json
from pathlib import Path

from tests.benchmark.vuln_corpus import CORPUS
from pyaegis.api import scan_code_string


def test_precision_recall():
    tp = fp = fn = 0
    details = []

    for sample in CORPUS:
        findings = scan_code_string(
            sample["code"],
            severity_filter=["HIGH", "CRITICAL"],
        )
        actual = len(findings)
        expected = sample["expected_findings"]

        if actual > 0 and expected > 0:
            tp += min(actual, expected)
        if actual > expected:
            fp += actual - expected
        if actual < expected:
            fn += expected - actual

        if expected == 0 and actual > 0:
            status = "FP"
        elif expected > 0 and actual == 0:
            status = "FN"
        elif expected > 0 and actual > 0:
            status = "TP"
        else:
            status = "TN"

        details.append({
            "label": sample["label"],
            "category": sample["category"],
            "expected": expected,
            "actual": actual,
            "status": status,
        })

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n" + "=" * 60)
    print("  PyAegis Benchmark Results")
    print("=" * 60)
    fmt = "{:<45} {:>6} {:>6}  {}"
    print(fmt.format("Sample", "Expect", "Actual", "Status"))
    print("-" * 65)
    for d in details:
        print(fmt.format(d["label"][:44], d["expected"], d["actual"], d["status"]))
    print("-" * 65)
    print(f"TP={tp}  FP={fp}  FN={fn}")
    print(f"Precision : {precision:.1%}")
    print(f"Recall    : {recall:.1%}")
    print(f"F1        : {f1:.1%}")
    print("=" * 60)

    # Persist JSON report for CI artifact upload
    report = {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "samples": details,
    }
    report_path = Path("benchmark_report.json")
    report_path.write_text(
        __import__("json").dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Report written to {report_path.resolve()}")

    # Quality gates
    assert precision >= 0.80, f"Precision {precision:.1%} < 80% threshold"
    assert recall >= 0.70, f"Recall {recall:.1%} < 70% threshold"
