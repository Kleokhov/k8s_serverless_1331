#!/usr/bin/env python3
"""Aggregate latency_metrics.py JSON outputs from repeated latency runs."""

from __future__ import annotations

import argparse
import collections
import json
import math
import statistics
from pathlib import Path
from typing import Iterable


RUN_METRICS = [
    ("submit_burst_seconds", "submit burst", "seconds"),
    ("scheduling_window_seconds", "scheduling window", "seconds"),
    ("node_pickup_window_seconds", "node pickup window", "seconds"),
    ("submit_to_start_window_seconds", "submit->start window", "seconds"),
    ("makespan_seconds", "makespan", "seconds"),
    ("scheduling_throughput_pods_per_sec", "scheduling throughput", "rate"),
    ("node_pickup_throughput_pods_per_sec", "node pickup throughput", "rate"),
    ("submit_to_start_throughput_pods_per_sec", "submit->start throughput", "rate"),
]

LATENCY_METRICS = [
    ("submit_to_schedule_s", "submit -> schedule"),
    ("schedule_to_bind_s", "schedule -> bind"),
    ("submit_to_bind_s", "submit -> bind"),
    ("bind_to_node_pickup_s", "bind -> node pickup"),
    ("schedule_to_node_pickup_s", "schedule -> node pickup"),
    ("submit_to_node_pickup_s", "submit -> node pickup"),
    ("node_pickup_to_start_s", "node pickup -> start"),
    ("schedule_to_start_s", "schedule -> start"),
    ("submit_to_start_s", "submit -> start"),
    ("workload_s", "workload"),
]

COUNT_FIELDS = [
    "requested_count",
    "observed_count",
    "scheduled_count",
    "node_pickup_count",
    "started_count",
    "finished_count",
]

PHASE_FIELDS = ["succeeded", "failed", "running", "pending", "other"]


def is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and not math.isnan(value)


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return ordered[int(k)]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def summarize(values: Iterable[object]) -> dict:
    cleaned = [float(v) for v in values if is_number(v)]
    if not cleaned:
        return {"count": 0}
    return {
        "count": len(cleaned),
        "min": min(cleaned),
        "max": max(cleaned),
        "mean": statistics.fmean(cleaned),
        "stdev": statistics.pstdev(cleaned) if len(cleaned) > 1 else 0.0,
        "p50": percentile(cleaned, 0.50),
        "p95": percentile(cleaned, 0.95),
        "p99": percentile(cleaned, 0.99),
    }


def fmt_value(value: float | None, unit: str) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "-"
    if unit == "rate":
        return f"{value:.2f} pods/sec"
    if unit == "count":
        return f"{value:.2f}"
    return f"{value:.3f}s"


def fmt_summary_row(name: str, summary: dict, unit: str = "seconds") -> str:
    if summary.get("count", 0) == 0:
        return f"  {name:<30} (no samples)"
    return (
        f"  {name:<30} "
        f"runs={summary['count']}  "
        f"avg={fmt_value(summary['mean'], unit)}  "
        f"min={fmt_value(summary['min'], unit)}  "
        f"max={fmt_value(summary['max'], unit)}"
    )


def first_non_empty(results: list[dict], key: str) -> object:
    for result in results:
        value = result.get(key)
        if value not in (None, ""):
            return value
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("result_files", nargs="+", type=Path)
    args = parser.parse_args()

    results = []
    for result_file in args.result_files:
        results.append(json.loads(result_file.read_text()))

    phase_totals = collections.Counter()
    failed_reason_totals = collections.Counter()
    for result in results:
        phase_totals.update(result.get("phase_counts") or {})
        failed_reason_totals.update(result.get("failed_reason_counts") or {})

    count_summaries = {
        key: summarize(result.get(key) for result in results)
        for key in COUNT_FIELDS
    }
    phase_summaries = {
        key: summarize((result.get("phase_counts") or {}).get(key, 0) for result in results)
        for key in PHASE_FIELDS
    }
    run_metric_summaries = {
        key: summarize(result.get(key) for result in results)
        for key, _, _ in RUN_METRICS
    }

    pooled_latency_values: dict[str, list[float]] = {key: [] for key, _ in LATENCY_METRICS}
    for result in results:
        for pod in result.get("per_pod") or []:
            for key, _ in LATENCY_METRICS:
                value = pod.get(key)
                if is_number(value):
                    pooled_latency_values[key].append(float(value))
    pooled_latency_summaries = {
        key: summarize(values)
        for key, values in pooled_latency_values.items()
    }

    requested_total = sum(int(result.get("requested_count") or 0) for result in results)
    observed_total = sum(int(result.get("observed_count") or 0) for result in results)
    aggregate = {
        "label": first_non_empty(results, "label"),
        "target": first_non_empty(results, "target"),
        "mode": first_non_empty(results, "mode"),
        "requested_count_per_run": first_non_empty(results, "requested_count"),
        "runs": len(results),
        "input_files": [str(path) for path in args.result_files],
        "totals": {
            "requested": requested_total,
            "observed": observed_total,
            "phase_counts": dict(phase_totals),
            "failed_reason_counts": dict(failed_reason_totals),
        },
        "count_summaries_per_run": count_summaries,
        "phase_summaries_per_run": phase_summaries,
        "run_metric_summaries": run_metric_summaries,
        "pooled_latency_summaries": pooled_latency_summaries,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(aggregate, indent=2))

    print()
    print(
        "=== Aggregate latency report: "
        f"label={aggregate['label']} target={aggregate['target']} "
        f"mode={aggregate['mode']} N={aggregate['requested_count_per_run']} "
        f"runs={aggregate['runs']} ==="
    )
    print(
        f"  requested={requested_total}  observed={observed_total}  "
        f"avg observed/run={fmt_value(count_summaries['observed_count'].get('mean'), 'count')}"
    )
    print(
        "  phases total: "
        f"succeeded={phase_totals.get('succeeded', 0)}  "
        f"failed={phase_totals.get('failed', 0)}  "
        f"running={phase_totals.get('running', 0)}  "
        f"pending={phase_totals.get('pending', 0)}  "
        f"other={phase_totals.get('other', 0)}"
    )
    print(
        "  phases avg/run: "
        f"succeeded={fmt_value(phase_summaries['succeeded'].get('mean'), 'count')}  "
        f"failed={fmt_value(phase_summaries['failed'].get('mean'), 'count')}  "
        f"running={fmt_value(phase_summaries['running'].get('mean'), 'count')}  "
        f"pending={fmt_value(phase_summaries['pending'].get('mean'), 'count')}  "
        f"other={fmt_value(phase_summaries['other'].get('mean'), 'count')}"
    )
    if failed_reason_totals:
        reasons = ", ".join(f"{reason}={count}" for reason, count in sorted(failed_reason_totals.items()))
        print(f"  failed reasons: {reasons}")

    print()
    print("  Run-level averages:")
    for key, label, unit in RUN_METRICS:
        print(fmt_summary_row(label, run_metric_summaries[key], unit))

    print()
    print("  Pooled per-pod latency aggregates:")
    for key, label in LATENCY_METRICS:
        summary = pooled_latency_summaries[key]
        if summary.get("count", 0) == 0:
            print(f"  {label:<30} (no samples)")
        else:
            print(
                f"  {label:<30} "
                f"n={summary['count']}  "
                f"avg={fmt_value(summary['mean'], 'seconds')}  "
                f"min={fmt_value(summary['min'], 'seconds')}  "
                f"max={fmt_value(summary['max'], 'seconds')}"
            )
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
