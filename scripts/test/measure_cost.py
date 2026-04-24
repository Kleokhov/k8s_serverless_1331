#!/usr/bin/env python3
"""
measure_stack_cost.py

Estimate the cost of the ctrlless-lambda SAM stack over a given time window
by pulling CloudWatch usage metrics and applying public list prices.
This bypasses the AWS Free Tier, which otherwise hides the cost in
Cost Explorer for a lightly-loaded stack.

Usage
-----
    pip install boto3
    python measure_stack_cost.py \
        --stack ctrlless-mt \
        --project masters-thesis-lambda-ctrl \
        --region us-east-1 \
        --hours 1

To measure a specific past window instead of "the last N hours":
    python measure_stack_cost.py --stack ctrlless-mt \
        --project masters-thesis-lambda-ctrl \
        --start 2026-04-23T14:00:00Z --end 2026-04-23T15:00:00Z

Resources covered
-----------------
    Lambda    - Invocations + Duration -> request + GB-s cost
    DynamoDB  - Consumed RRU/WRU (table + GSIs) + storage proration
    SQS       - Sent / Received / EmptyReceives / Deleted -> request cost
    CW Logs   - IncomingBytes per /aws/lambda/* log group -> ingestion cost
    VPC       - Interface endpoints tagged with Project -> ENI-hours

Not covered (small for this stack, but edit if you care)
    - DynamoDB Streams read request units (AWS/DynamoDB has no clean metric)
    - CloudWatch Logs storage (usually small vs ingestion)
    - Data transfer through VPC endpoints
    - EventBridge scheduled rule invocations (free for native AWS events)
    - SSM Parameter Store GetParameter (standard tier: free)
"""
from __future__ import annotations

import argparse
import datetime as dt
import sys

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Prices. us-east-1 list, reflecting the Nov-2024 DynamoDB on-demand 50% cut.
# Verify at https://aws.amazon.com/<service>/pricing/ for your region.
# ---------------------------------------------------------------------------
PRICE = {
    # Lambda (x86_64)
    "lambda_request":          0.20 / 1_000_000,
    "lambda_gb_second":        0.0000166667,

    # SQS
    "sqs_standard_request":    0.40 / 1_000_000,
    "sqs_fifo_request":        0.50 / 1_000_000,

    # DynamoDB on-demand, Standard table class (post Nov-2024 price cut)
    "ddb_write_request_unit":  0.625 / 1_000_000,
    "ddb_read_request_unit":   0.125 / 1_000_000,
    "ddb_storage_gb_month":    0.25,

    # CloudWatch Logs
    "logs_ingestion_gb":       0.50,

    # VPC Interface Endpoints: per-ENI-hour (one ENI per AZ per endpoint)
    "vpc_endpoint_eni_hour":   0.01,
}

HOURS_PER_MONTH = 730  # AWS billing convention: 24 * 365.25 / 12


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--stack",
        required=True,
        help="CloudFormation stack name passed to sam deploy --stack-name (not ResourcePrefix)",
    )
    p.add_argument("--project", required=True,
                   help="Value of the Project tag (used to find VPC endpoints)")
    p.add_argument("--region",  default="us-east-1")
    p.add_argument("--hours",   type=float, default=1.0,
                   help="Window length ending now, in hours (default 1.0)")
    p.add_argument("--start",   help="ISO-8601 start (overrides --hours)")
    p.add_argument("--end",     help="ISO-8601 end (defaults to now)")
    return p.parse_args()


def resolve_window(args: argparse.Namespace) -> tuple[dt.datetime, dt.datetime]:
    end = (dt.datetime.fromisoformat(args.end.replace("Z", "+00:00"))
           if args.end else dt.datetime.now(dt.timezone.utc))
    start = (dt.datetime.fromisoformat(args.start.replace("Z", "+00:00"))
             if args.start else end - dt.timedelta(hours=args.hours))
    if start >= end:
        sys.exit("start must be before end")
    return start, end


# ---------------------------------------------------------------------------
# CloudWatch helper
# ---------------------------------------------------------------------------
def cw_sum(cw, namespace: str, metric: str, dims: dict,
           start: dt.datetime, end: dt.datetime) -> float:
    """Sum of a metric over [start, end], in hourly buckets."""
    resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric,
        Dimensions=[{"Name": k, "Value": v} for k, v in dims.items()],
        StartTime=start, EndTime=end,
        Period=3600,
        Statistics=["Sum"],
    )
    return sum(d["Sum"] for d in resp["Datapoints"])


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def discover(cfn, ec2, stack_name: str, project_tag: str):
    funcs, tables, queues = [], [], []
    try:
        pages = cfn.get_paginator("list_stack_resources").paginate(StackName=stack_name)
        for page in pages:
            for r in page["StackResourceSummaries"]:
                t, pid = r["ResourceType"], r["PhysicalResourceId"]
                if t == "AWS::Lambda::Function":
                    funcs.append(pid)
                elif t == "AWS::DynamoDB::Table":
                    tables.append(pid)
                elif t == "AWS::SQS::Queue":
                    # PhysicalResourceId is the queue URL
                    queues.append(pid.rsplit("/", 1)[-1])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "ValidationError":
            msg = e.response.get("Error", {}).get("Message", str(e))
            if "does not exist" in msg:
                sys.exit(
                    f"CloudFormation stack '{stack_name}' was not found. "
                    "Pass the value used with 'sam deploy --stack-name', not the "
                    "template's ResourcePrefix parameter."
                )
        raise

    # VPC interface endpoints: may be inside or outside the stack,
    # so discover them by Project tag.
    endpoints = []
    resp = ec2.describe_vpc_endpoints(
        Filters=[{"Name": "tag:Project", "Values": [project_tag]}]
    )
    for ep in resp.get("VpcEndpoints", []):
        if ep["VpcEndpointType"] == "Interface":
            endpoints.append({
                "id":        ep["VpcEndpointId"],
                "service":   ep["ServiceName"].rsplit(".", 1)[-1],
                "eni_count": len(ep["NetworkInterfaceIds"]),
            })
    return funcs, tables, queues, endpoints


# ---------------------------------------------------------------------------
# Per-service cost
# ---------------------------------------------------------------------------
def lambda_rows(cw, lam, funcs, start, end):
    rows = []
    for f in funcs:
        invocations = cw_sum(cw, "AWS/Lambda", "Invocations",
                             {"FunctionName": f}, start, end)
        duration_ms = cw_sum(cw, "AWS/Lambda", "Duration",
                             {"FunctionName": f}, start, end)
        memory_mb = lam.get_function_configuration(FunctionName=f)["MemorySize"]
        gb_seconds = (duration_ms / 1000.0) * (memory_mb / 1024.0)
        cost = (invocations * PRICE["lambda_request"]
                + gb_seconds * PRICE["lambda_gb_second"])
        rows.append({
            "name": f, "invocations": int(invocations),
            "duration_s": duration_ms / 1000.0, "memory_mb": memory_mb,
            "gb_seconds": gb_seconds, "cost": cost,
        })
    return rows


def ddb_rows(cw, ddb, tables, start, end):
    rows = []
    hours = (end - start).total_seconds() / 3600.0
    for t in tables:
        desc = ddb.describe_table(TableName=t)["Table"]

        read_units  = cw_sum(cw, "AWS/DynamoDB", "ConsumedReadCapacityUnits",
                             {"TableName": t}, start, end)
        write_units = cw_sum(cw, "AWS/DynamoDB", "ConsumedWriteCapacityUnits",
                             {"TableName": t}, start, end)

        # GSIs are billed separately; their consumption shows up
        # under the (TableName, GlobalSecondaryIndexName) dimension pair.
        for gsi in desc.get("GlobalSecondaryIndexes") or []:
            read_units  += cw_sum(cw, "AWS/DynamoDB", "ConsumedReadCapacityUnits",
                                  {"TableName": t,
                                   "GlobalSecondaryIndexName": gsi["IndexName"]},
                                  start, end)
            write_units += cw_sum(cw, "AWS/DynamoDB", "ConsumedWriteCapacityUnits",
                                  {"TableName": t,
                                   "GlobalSecondaryIndexName": gsi["IndexName"]},
                                  start, end)

        size_gb = desc.get("TableSizeBytes", 0) / (1024 ** 3)
        storage_cost = (size_gb * PRICE["ddb_storage_gb_month"]
                        * (hours / HOURS_PER_MONTH))
        cost = (read_units  * PRICE["ddb_read_request_unit"]
                + write_units * PRICE["ddb_write_request_unit"]
                + storage_cost)
        rows.append({
            "name": t, "rru": read_units, "wru": write_units,
            "size_gb": size_gb, "storage_cost": storage_cost, "cost": cost,
        })
    return rows


def sqs_rows(cw, queues, start, end):
    rows = []
    for q in queues:
        sent    = cw_sum(cw, "AWS/SQS", "NumberOfMessagesSent",     {"QueueName": q}, start, end)
        recv    = cw_sum(cw, "AWS/SQS", "NumberOfMessagesReceived", {"QueueName": q}, start, end)
        empty   = cw_sum(cw, "AWS/SQS", "NumberOfEmptyReceives",    {"QueueName": q}, start, end)
        deleted = cw_sum(cw, "AWS/SQS", "NumberOfMessagesDeleted",  {"QueueName": q}, start, end)
        # 1 billable API request per Send, per Receive (empty or not), per Delete.
        # (ChangeMessageVisibility etc. also count but have no simple metric; ignored.)
        requests = sent + recv + empty + deleted
        unit_price = (PRICE["sqs_fifo_request"] if q.endswith(".fifo")
                      else PRICE["sqs_standard_request"])
        rows.append({
            "name": q, "sent": int(sent), "received": int(recv),
            "empty": int(empty), "deleted": int(deleted),
            "requests": int(requests), "cost": requests * unit_price,
        })
    return rows


def logs_rows(cw, funcs, start, end):
    rows = []
    for f in funcs:
        lg = f"/aws/lambda/{f}"
        incoming = cw_sum(cw, "AWS/Logs", "IncomingBytes",
                          {"LogGroupName": lg}, start, end)
        gb = incoming / (1024 ** 3)
        rows.append({
            "name": lg, "bytes": int(incoming), "gb": gb,
            "cost": gb * PRICE["logs_ingestion_gb"],
        })
    return rows


def vpce_rows(endpoints, start, end):
    hours = (end - start).total_seconds() / 3600.0
    return [{
        "name": f"{ep['id']} ({ep['service']})",
        "eni_count": ep["eni_count"],
        "eni_hours": ep["eni_count"] * hours,
        "cost": ep["eni_count"] * hours * PRICE["vpc_endpoint_eni_hour"],
    } for ep in endpoints]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_section(title, rows, cols):
    print(f"\n=== {title} ===")
    if not rows:
        print("  (none)")
        return
    header = "  ".join(f"{c:>{w}}" for c, w in cols)
    print("  " + header)
    print("  " + "-" * len(header))
    for r in rows:
        cells = []
        for key, w in cols:
            v = r.get(key, "")
            if key == "cost":
                cells.append(f"${v:>{w-1}.6f}")
            elif isinstance(v, float):
                cells.append(f"{v:>{w}.2f}")
            else:
                cells.append(f"{str(v):>{w}}")
        print("  " + "  ".join(cells))
    print(f"  {'subtotal':>{cols[0][1]}}: ${sum(r['cost'] for r in rows):.6f}")


def main():
    args = parse_args()
    start, end = resolve_window(args)
    hours = (end - start).total_seconds() / 3600.0
    print(f"Window: {start.isoformat()}  ->  {end.isoformat()}  ({hours:.3f} h)")
    print(f"Region: {args.region}   Stack: {args.stack}   Project tag: {args.project}")

    session = boto3.Session(region_name=args.region)
    cfn, ec2 = session.client("cloudformation"), session.client("ec2")
    cw, lam  = session.client("cloudwatch"),     session.client("lambda")
    ddb      = session.client("dynamodb")

    funcs, tables, queues, endpoints = discover(cfn, ec2, args.stack, args.project)

    lam_r  = lambda_rows(cw, lam, funcs, start, end)
    ddb_r  = ddb_rows(cw, ddb, tables, start, end)
    sqs_r  = sqs_rows(cw, queues, start, end)
    logs_r = logs_rows(cw, funcs, start, end)
    vpce_r = vpce_rows(endpoints, start, end)

    print_section("Lambda",       lam_r,
                  [("name", 42), ("invocations", 11), ("duration_s", 10),
                   ("gb_seconds", 10), ("cost", 12)])
    print_section("DynamoDB",     ddb_r,
                  [("name", 42), ("rru", 12), ("wru", 12),
                   ("size_gb", 9), ("cost", 12)])
    print_section("SQS",          sqs_r,
                  [("name", 42), ("sent", 8), ("received", 9),
                   ("empty", 8), ("deleted", 8), ("cost", 12)])
    print_section("CW Logs",      logs_r,
                  [("name", 42), ("bytes", 12), ("gb", 9), ("cost", 12)])
    print_section("VPC Endpoints", vpce_r,
                  [("name", 42), ("eni_count", 10), ("eni_hours", 11), ("cost", 12)])

    total = sum(r["cost"] for rs in (lam_r, ddb_r, sqs_r, logs_r, vpce_r) for r in rs)
    hourly  = total / hours
    monthly = hourly * HOURS_PER_MONTH

    print()
    print(f"  Window total:                  ${total:12.6f}")
    print(f"  Projected hourly:              ${hourly:12.6f}")
    print(f"  Projected monthly (x{HOURS_PER_MONTH}):        ${monthly:12.2f}")
    print()
    print("  Prices: us-east-1 list, pre-Free-Tier, pre-Savings-Plans.")
    print("  Edit PRICE{} at the top of this file for your region.")


if __name__ == "__main__":
    main()
