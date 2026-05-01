#!/usr/bin/env python3
"""
Compute scheduling, node-pickup, and submit-to-start latency / throughput
metrics for a batch of pods. Inputs:

  --pods-json    snapshot of `kubectl get pods -o json`
  --events-json  optional snapshot of `kubectl get events -o json`

Per-pod stages tracked (these are the four timestamps the pipeline cares about):

  1) submitted          apiserver received the pod
                        - metadata.creationTimestamp        (1s, metav1.Time)

  2) scheduled          scheduler selected or bound the pod to a node
                        - Event{reason=Scheduled} eventTime (us, metav1.MicroTime)
                        - annotation serverless-scheduler.ctrlless.io/scheduled-at (ns) [serverless node choice]
                        - annotation serverless-scheduler.ctrlless.io/bound-at (ns) [serverless bind fallback]
                        - PodScheduled condition            (1s) [fallback]

  3) node_pickup       kubelet on the node first acted on the pod
                       - Event{reason=Dispatched} eventTime (us)              [custom legacy reason]
                       - annotation serverless-kubelet.ctrlless.io/dispatched-at (any precision) [custom]
                       - first kubelet event for the pod (Pulling/Pulled/Created) eventTime (us) [proxy]
                       Kubernetes has no standard field for this stage. The
                       serverless kubelet should emit a custom event or
                       annotation when it picks up an assignment; without
                       that, this stage is reported as null and only the
                       Pulling/Pulled/Created proxy is used (which can be
                       absent for pre-pulled images).

  4) started_on_node    container actually started executing on the runtime
                        - Event{reason=Started} eventTime   (us)
                        - containerStatuses[0].state.{running|terminated}.startedAt (1s) [fallback]

Plus a fifth, reported separately as workload runtime:

     finished_on_node   container exited
                        - containerStatuses[0].state.terminated.finishedAt (1s)

Per-pod latencies (seconds):
  submit_to_schedule_s       scheduled        - submitted
  schedule_to_bind_s         bound            - scheduled            (serverless annotation only)
  submit_to_bind_s           bound            - submitted            (serverless annotation only)
  bind_to_node_pickup_s      node_pickup      - bound                (serverless annotation only)
  schedule_to_node_pickup_s  node_pickup      - scheduled            (null if no node pickup ts)
  submit_to_node_pickup_s    node_pickup      - submitted            (shown as end-to-end; null if no node pickup ts)
  node_pickup_to_start_s     started_on_node  - node_pickup          (null if no node pickup ts)
  schedule_to_start_s        started_on_node  - scheduled            (fallback when node pickup missing)
  submit_to_start_s          started_on_node  - submitted
  workload_s                 finished_on_node - started_on_node

Batch-level numbers:
  scheduling_throughput       count_scheduled   / (max(scheduled)   - min(submitted))
  node_pickup_throughput      count_node_pickup / (max(node_pickup) - min(submitted)) [shown as end-to-end]
  submit_to_start_throughput  count_started     / (max(started)     - min(submitted))
  makespan                    max(started) - min(submitted)

Resolution: pod conditions and creationTimestamp are second-precision; events
provide microsecond precision via eventTime. The script prefers event
timestamps where available and transparently falls back to status fields,
so a run that mixes both will report mixed precision (which may show 0.0s for
very fast stages without events).
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SCHEDULER_REASONS = ("Scheduled",)
NODE_PICKUP_REASONS = ("Dispatched",)
NODE_PICKUP_PROXY_REASONS = ("Pulling", "Pulled", "Created")
STARTED_REASONS = ("Started",)
SCHEDULED_ANNOTATION = "serverless-scheduler.ctrlless.io/scheduled-at"
BOUND_ANNOTATION = "serverless-scheduler.ctrlless.io/bound-at"
NODE_PICKUP_ANNOTATION = "serverless-kubelet.ctrlless.io/dispatched-at"


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def find_condition(pod: dict, cond_type: str) -> str | None:
    for cond in (pod.get("status") or {}).get("conditions") or []:
        if cond.get("type") == cond_type:
            return cond.get("lastTransitionTime")
    return None


def first_container_status(pod: dict) -> dict | None:
    statuses = (pod.get("status") or {}).get("containerStatuses") or []
    return statuses[0] if statuses else None


def container_start_iso(pod: dict) -> str | None:
    status = first_container_status(pod)
    if not status:
        return None
    state = status.get("state") or {}
    running = state.get("running") or {}
    if running.get("startedAt"):
        return running["startedAt"]
    terminated = state.get("terminated") or {}
    return terminated.get("startedAt")


def container_finish_iso(pod: dict) -> str | None:
    status = first_container_status(pod)
    if not status:
        return None
    terminated = (status.get("state") or {}).get("terminated") or {}
    return terminated.get("finishedAt")


def compact_conditions(status: dict) -> list[dict]:
    out = []
    for cond in status.get("conditions") or []:
        out.append(
            {
                "type": cond.get("type"),
                "status": cond.get("status"),
                "reason": cond.get("reason"),
                "message": cond.get("message"),
                "last_transition_time": cond.get("lastTransitionTime"),
            }
        )
    return out


def compact_container_states(status: dict) -> list[dict]:
    out = []
    for container_status in status.get("containerStatuses") or []:
        state = container_status.get("state") or {}
        last_state = container_status.get("lastState") or {}
        item = {
            "name": container_status.get("name"),
            "ready": container_status.get("ready"),
            "restart_count": container_status.get("restartCount"),
        }
        for key in ("waiting", "running", "terminated"):
            if state.get(key):
                item["state"] = key
                item["state_detail"] = state.get(key)
                break
        for key in ("waiting", "running", "terminated"):
            if last_state.get(key):
                item["last_state"] = key
                item["last_state_detail"] = last_state.get(key)
                break
        out.append(item)
    return out


def diff_seconds(later: datetime | None, earlier: datetime | None) -> float | None:
    if later is None or earlier is None:
        return None
    return (later - earlier).total_seconds()


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    if len(values) == 1:
        return values[0]
    s = sorted(values)
    k = (len(s) - 1) * p
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return s[int(k)]
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summarize(values: Iterable[float | None]) -> dict:
    cleaned = [v for v in values if v is not None and not math.isnan(v)]
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


def fmt_seconds(value: float | None) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "-"
    return f"{value:.3f}s"


def fmt_summary_row(name: str, summary: dict) -> str:
    if summary.get("count", 0) == 0:
        return f"    {name:<28} no samples"
    return (
        f"    {name:<28} "
        f"n={summary['count']}  "
        f"avg={fmt_seconds(summary['mean'])}  "
        f"min={fmt_seconds(summary['min'])}  "
        f"p50={fmt_seconds(summary['p50'])}  "
        f"p95={fmt_seconds(summary['p95'])}  "
        f"p99={fmt_seconds(summary['p99'])}  "
        f"max={fmt_seconds(summary['max'])}"
    )


def fmt_throughput(value: float | None, count: int, noun: str) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return f"- ({count} {noun})"
    return f"{value:.2f} pods/sec ({count} {noun})"


def index_pod_events(events_path: Path | None) -> dict[str, dict[str, datetime]]:
    """Return {pod_uid_or_name: {reason: earliest_event_time}}.

    Pods are keyed by both uid and namespace/name so the lookup works no
    matter which the pod object exposes.
    """
    if events_path is None or not events_path.exists():
        return {}
    try:
        raw = json.loads(events_path.read_text())
    except json.JSONDecodeError:
        return {}
    idx: dict[str, dict[str, datetime]] = {}
    for ev in raw.get("items") or []:
        inv = ev.get("involvedObject") or ev.get("regarding") or {}
        if inv.get("kind") != "Pod":
            continue
        reason = ev.get("reason")
        if not reason:
            continue
        meta = ev.get("metadata") or {}
        series = ev.get("series") or {}
        ts_str = (
            ev.get("eventTime")
            or series.get("lastObservedTime")
            or ev.get("firstTimestamp")
            or ev.get("lastTimestamp")
            or ev.get("deprecatedFirstTimestamp")
            or ev.get("deprecatedLastTimestamp")
            or meta.get("creationTimestamp")
        )
        ts = parse_iso(ts_str)
        if ts is None:
            continue
        keys = []
        if inv.get("uid"):
            keys.append(inv["uid"])
        ns = inv.get("namespace")
        name = inv.get("name")
        if ns and name:
            keys.append(f"{ns}/{name}")
        if name:
            keys.append(name)
        for key in keys:
            d = idx.setdefault(key, {})
            existing = d.get(reason)
            if existing is None or ts < existing:
                d[reason] = ts
    return idx


def lookup_pod_events(idx: dict[str, dict[str, datetime]], pod: dict) -> dict[str, datetime]:
    meta = pod.get("metadata") or {}
    for key in (meta.get("uid"), f"{meta.get('namespace')}/{meta.get('name')}", meta.get("name")):
        if key and key in idx:
            return idx[key]
    return {}


def first_event_time(
    pod_events: dict[str, datetime], reasons: Iterable[str]
) -> datetime | None:
    candidates = [pod_events[r] for r in reasons if r in pod_events]
    return min(candidates) if candidates else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pods-json", required=True, type=Path)
    parser.add_argument("--events-json", type=Path, default=None,
                        help="Optional `kubectl get events -o json` snapshot. "
                             "Provides microsecond eventTime for Scheduled/Started/Dispatched.")
    parser.add_argument("--label", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--requested-count", required=True, type=int)
    parser.add_argument("--workload-sleep", required=True)
    parser.add_argument("--submit-start", required=True)
    parser.add_argument("--submit-end", required=True)
    parser.add_argument("--finish", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--kubeconfig", default="")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    raw = json.loads(args.pods_json.read_text())
    items = raw.get("items") or []
    events_idx = index_pod_events(args.events_json)

    per_pod = []
    earliest_submitted = None
    latest_scheduled = None
    latest_node_pickup = None
    latest_finished = None
    earliest_started = None
    latest_started = None

    succeeded = 0
    failed = 0
    pending = 0
    running = 0
    other = 0

    sources_used = {
        "scheduled_from_event": 0,
        "scheduled_from_annotation": 0,
        "scheduled_from_bound_annotation": 0,
        "scheduled_from_condition": 0,
        "node_pickup_from_event": 0,
        "node_pickup_from_annotation": 0,
        "node_pickup_from_proxy": 0,
        "node_pickup_missing": 0,
        "started_from_event": 0,
        "started_from_status": 0,
    }

    for pod in items:
        meta = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        status = pod.get("status") or {}
        annotations = meta.get("annotations") or {}

        pod_events = lookup_pod_events(events_idx, pod)

        submitted = parse_iso(meta.get("creationTimestamp"))

        scheduled_event = first_event_time(pod_events, SCHEDULER_REASONS)
        scheduled_annotation = parse_iso(annotations.get(SCHEDULED_ANNOTATION))
        bound_annotation = parse_iso(annotations.get(BOUND_ANNOTATION))
        scheduled_cond = parse_iso(find_condition(pod, "PodScheduled"))
        scheduled = scheduled_event or scheduled_annotation or bound_annotation or scheduled_cond
        if scheduled_event is not None:
            sources_used["scheduled_from_event"] += 1
        elif scheduled_annotation is not None:
            sources_used["scheduled_from_annotation"] += 1
        elif bound_annotation is not None:
            sources_used["scheduled_from_bound_annotation"] += 1
        elif scheduled_cond is not None:
            sources_used["scheduled_from_condition"] += 1

        node_pickup_event = first_event_time(pod_events, NODE_PICKUP_REASONS)
        node_pickup_annotation = parse_iso(annotations.get(NODE_PICKUP_ANNOTATION))
        node_pickup_proxy = first_event_time(pod_events, NODE_PICKUP_PROXY_REASONS)
        if node_pickup_event is not None:
            node_pickup = node_pickup_event
            sources_used["node_pickup_from_event"] += 1
        elif node_pickup_annotation is not None:
            node_pickup = node_pickup_annotation
            sources_used["node_pickup_from_annotation"] += 1
        elif node_pickup_proxy is not None:
            node_pickup = node_pickup_proxy
            sources_used["node_pickup_from_proxy"] += 1
        else:
            node_pickup = None
            sources_used["node_pickup_missing"] += 1

        started_event = first_event_time(pod_events, STARTED_REASONS)
        started_status = parse_iso(container_start_iso(pod))
        started_on_node = started_event or started_status
        if started_event is not None:
            sources_used["started_from_event"] += 1
        elif started_status is not None:
            sources_used["started_from_status"] += 1

        finished_on_node = parse_iso(container_finish_iso(pod))

        phase = status.get("phase")
        node = spec.get("nodeName") or ""

        if phase == "Succeeded":
            succeeded += 1
        elif phase == "Failed":
            failed += 1
        elif phase == "Running":
            running += 1
        elif phase == "Pending":
            pending += 1
        else:
            other += 1

        if submitted is not None:
            if earliest_submitted is None or submitted < earliest_submitted:
                earliest_submitted = submitted
        if scheduled is not None:
            if latest_scheduled is None or scheduled > latest_scheduled:
                latest_scheduled = scheduled
        if node_pickup is not None:
            if latest_node_pickup is None or node_pickup > latest_node_pickup:
                latest_node_pickup = node_pickup
        if started_on_node is not None:
            if earliest_started is None or started_on_node < earliest_started:
                earliest_started = started_on_node
            if latest_started is None or started_on_node > latest_started:
                latest_started = started_on_node
        if finished_on_node is not None:
            if latest_finished is None or finished_on_node > latest_finished:
                latest_finished = finished_on_node

        per_pod.append(
            {
                "name": meta.get("name"),
                "uid": meta.get("uid"),
                "node": node,
                "phase": phase,
                "status_reason": status.get("reason"),
                "status_message": status.get("message"),
                "deletion_timestamp": meta.get("deletionTimestamp"),
                "failed_before_start": phase == "Failed" and started_on_node is None,
                "conditions": compact_conditions(status),
                "container_states": compact_container_states(status),
                "event_reasons": {r: ts.isoformat() for r, ts in sorted(pod_events.items())},
                "submitted": submitted.isoformat() if submitted else None,
                "scheduled": scheduled.isoformat() if scheduled else None,
                "scheduled_source": (
                    "event" if scheduled_event
                    else "annotation" if scheduled_annotation
                    else "bound_annotation" if bound_annotation
                    else "condition" if scheduled_cond
                    else None
                ),
                "serverless_scheduled_at": scheduled_annotation.isoformat() if scheduled_annotation else None,
                "serverless_bound_at": bound_annotation.isoformat() if bound_annotation else None,
                "node_pickup": node_pickup.isoformat() if node_pickup else None,
                "node_pickup_source": (
                    "event" if node_pickup_event
                    else "annotation" if node_pickup_annotation
                    else "proxy_kubelet_event" if node_pickup_proxy
                    else None
                ),
                "started_on_node": started_on_node.isoformat() if started_on_node else None,
                "started_source": "event" if started_event else ("status" if started_status else None),
                "finished_on_node": finished_on_node.isoformat() if finished_on_node else None,
                "submit_to_schedule_s": diff_seconds(scheduled, submitted),
                "schedule_to_bind_s": diff_seconds(bound_annotation, scheduled),
                "submit_to_bind_s": diff_seconds(bound_annotation, submitted),
                "bind_to_node_pickup_s": diff_seconds(node_pickup, bound_annotation),
                "schedule_to_node_pickup_s": diff_seconds(node_pickup, scheduled),
                "submit_to_node_pickup_s": diff_seconds(node_pickup, submitted),
                "node_pickup_to_start_s": diff_seconds(started_on_node, node_pickup),
                "schedule_to_start_s": diff_seconds(started_on_node, scheduled),
                "submit_to_start_s": diff_seconds(started_on_node, submitted),
                "workload_s": diff_seconds(finished_on_node, started_on_node),
            }
        )

    summaries = {
        "submit_to_schedule_s": summarize(p["submit_to_schedule_s"] for p in per_pod),
        "schedule_to_bind_s": summarize(p["schedule_to_bind_s"] for p in per_pod),
        "submit_to_bind_s": summarize(p["submit_to_bind_s"] for p in per_pod),
        "bind_to_node_pickup_s": summarize(p["bind_to_node_pickup_s"] for p in per_pod),
        "schedule_to_node_pickup_s": summarize(p["schedule_to_node_pickup_s"] for p in per_pod),
        "submit_to_node_pickup_s": summarize(p["submit_to_node_pickup_s"] for p in per_pod),
        "node_pickup_to_start_s": summarize(p["node_pickup_to_start_s"] for p in per_pod),
        "schedule_to_start_s": summarize(p["schedule_to_start_s"] for p in per_pod),
        "submit_to_start_s": summarize(p["submit_to_start_s"] for p in per_pod),
        "workload_s": summarize(p["workload_s"] for p in per_pod),
    }

    scheduled_count = sum(1 for p in per_pod if p["scheduled"])
    node_pickup_count = sum(1 for p in per_pod if p["node_pickup"])
    started_count = sum(1 for p in per_pod if p["started_on_node"])
    finished_count = sum(1 for p in per_pod if p["finished_on_node"])

    sched_window = diff_seconds(latest_scheduled, earliest_submitted)
    node_pickup_window = diff_seconds(latest_node_pickup, earliest_submitted)
    submit_to_start_window = diff_seconds(latest_started, earliest_submitted)
    makespan = submit_to_start_window
    sched_throughput = (scheduled_count / sched_window) if sched_window and sched_window > 0 else None
    node_pickup_throughput = (node_pickup_count / node_pickup_window) if node_pickup_window and node_pickup_window > 0 else None
    submit_to_start_throughput = (started_count / submit_to_start_window) if submit_to_start_window and submit_to_start_window > 0 else None
    submit_burst_window = diff_seconds(parse_iso(args.submit_end), parse_iso(args.submit_start))
    failed_reason_counts = collections.Counter(
        (
            p.get("status_reason")
            or ("OutOfcpu" if "OutOfcpu" in p.get("event_reasons", {}) else None)
            or "unknown"
        )
        for p in per_pod
        if p.get("phase") == "Failed"
    )

    result = {
        "label": args.label,
        "target": args.target,
        "mode": args.mode,
        "kubeconfig": args.kubeconfig,
        "run_id": args.run_id,
        "requested_count": args.requested_count,
        "observed_count": len(per_pod),
        "workload_sleep_seconds": args.workload_sleep,
        "submit_start": args.submit_start,
        "submit_end": args.submit_end,
        "finish_observed": args.finish,
        "primary_latency_definition": "submitted_to_started",
        "submit_burst_seconds": submit_burst_window,
        "events_json_used": args.events_json is not None and args.events_json.exists(),
        "timestamp_sources": sources_used,
        "phase_counts": {
            "succeeded": succeeded,
            "failed": failed,
            "running": running,
            "pending": pending,
            "other": other,
        },
        "failed_reason_counts": dict(failed_reason_counts),
        "scheduled_count": scheduled_count,
        "node_pickup_count": node_pickup_count,
        "started_count": started_count,
        "finished_count": finished_count,
        "earliest_submitted": earliest_submitted.isoformat() if earliest_submitted else None,
        "latest_scheduled": latest_scheduled.isoformat() if latest_scheduled else None,
        "latest_node_pickup": latest_node_pickup.isoformat() if latest_node_pickup else None,
        "earliest_started": earliest_started.isoformat() if earliest_started else None,
        "latest_started": latest_started.isoformat() if latest_started else None,
        "latest_finished": latest_finished.isoformat() if latest_finished else None,
        "scheduling_window_seconds": sched_window,
        "node_pickup_window_seconds": node_pickup_window,
        "submit_to_start_window_seconds": submit_to_start_window,
        "makespan_seconds": makespan,
        "scheduling_throughput_pods_per_sec": sched_throughput,
        "node_pickup_throughput_pods_per_sec": node_pickup_throughput,
        "submit_to_start_throughput_pods_per_sec": submit_to_start_throughput,
        "summaries": summaries,
        "per_pod": per_pod,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, default=str))

    print()
    print(f"=== Latency report: label={args.label} target={args.target} mode={args.mode} N={args.requested_count} ===")
    print("  Pods")
    print(
        f"    observed={result['observed_count']}  succeeded={succeeded}  failed={failed}  "
        f"running={running}  pending={pending}  other={other}"
    )
    if failed_reason_counts:
        reasons = ", ".join(f"{reason}={count}" for reason, count in sorted(failed_reason_counts.items()))
        print(f"    failed reasons: {reasons}")

    print("  Timestamp sources")
    print(f"    events used:      {result['events_json_used']}")
    print(
        "    scheduled:        "
        f"event={sources_used['scheduled_from_event']}  "
        f"annotation={sources_used['scheduled_from_annotation']}  "
        f"bound_annotation={sources_used['scheduled_from_bound_annotation']}  "
        f"condition={sources_used['scheduled_from_condition']}"
    )
    print(
        "    node pickup:      "
        f"event={sources_used['node_pickup_from_event']}  "
        f"annotation={sources_used['node_pickup_from_annotation']}  "
        f"proxy={sources_used['node_pickup_from_proxy']}  "
        f"missing={sources_used['node_pickup_missing']}"
    )
    print(f"    started:          event={sources_used['started_from_event']}  status={sources_used['started_from_status']}")

    print("  Windows")
    print(f"    submit burst:     {fmt_seconds(submit_burst_window)} (kubectl apply duration)")
    print(f"    scheduling:       {fmt_seconds(sched_window)} (min submitted -> max scheduled)")
    print(f"    end-to-end:       {fmt_seconds(node_pickup_window)} (min submitted -> max node pickup)")
    if submit_to_start_window is not None:
        print(f"    submit -> start:  {fmt_seconds(submit_to_start_window)} (min submitted -> max started)")
    print(f"    makespan:         {fmt_seconds(makespan)}")

    print("  Throughput")
    print(f"    scheduling:       {fmt_throughput(sched_throughput, scheduled_count, 'scheduled')}")
    print(f"    end-to-end:       {fmt_throughput(node_pickup_throughput, node_pickup_count, 'node pickups')}")
    if submit_to_start_throughput is not None:
        print(f"    submit -> start:  {fmt_throughput(submit_to_start_throughput, started_count, 'started')}")

    print("  Per-pod latency aggregates")
    print(fmt_summary_row("submit -> schedule", summaries["submit_to_schedule_s"]))
    if summaries["schedule_to_bind_s"].get("count", 0):
        print(fmt_summary_row("schedule -> bind", summaries["schedule_to_bind_s"]))
    if summaries["submit_to_bind_s"].get("count", 0):
        print(fmt_summary_row("submit -> bind", summaries["submit_to_bind_s"]))
    if summaries["bind_to_node_pickup_s"].get("count", 0):
        print(fmt_summary_row("bind -> node pickup", summaries["bind_to_node_pickup_s"]))
    if summaries["schedule_to_node_pickup_s"].get("count", 0):
        print(fmt_summary_row("schedule -> node pickup", summaries["schedule_to_node_pickup_s"]))
    print(fmt_summary_row("end-to-end", summaries["submit_to_node_pickup_s"]))
    if summaries["node_pickup_to_start_s"].get("count", 0):
        print(fmt_summary_row("node pickup -> start", summaries["node_pickup_to_start_s"]))
    if summaries["schedule_to_start_s"].get("count", 0):
        print(fmt_summary_row("schedule -> start", summaries["schedule_to_start_s"]))
    if summaries["submit_to_start_s"].get("count", 0):
        print(fmt_summary_row("submit -> start", summaries["submit_to_start_s"]))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
