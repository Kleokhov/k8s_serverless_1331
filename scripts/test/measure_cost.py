#!/usr/bin/env python3
"""
measure_cost.py

Estimate the cost of the serverless pipeline deployed by
scripts/deploy_serverless_pipeline.sh over a given time window, by pulling
CloudWatch usage metrics and applying public list prices. This bypasses the
AWS Free Tier, which otherwise hides the cost in Cost Explorer for a
lightly-loaded stack.

The pipeline spans three deployments:
  1. Lambda apiserver SAM stack (default: ctrlless-serverless-apiserver)
       - Lambda function fronted by API Gateway REST
       - DynamoDB tables precreated out-of-band by precreate_dynamo_tables.sh
         (not owned by the stack, so discovered by table-name prefix)
  2. Lambda scheduler/controllers SAM stack (default: ctrlless-serverless-lambda)
       - 4+ Lambda controllers, SQS queues, DynamoDB state tables,
         optionally VPC interface endpoints
  3. Serverless kubelet EC2 workers (tagged Project=<prefix>,
     Role=serverless-worker), provisioned by deploy_serverless_kubelet.sh

Usage
-----
    pip install boto3
    python measure_cost.py --hours 1

    # With custom names / project tag:
    python measure_cost.py \\
        --apiserver-stack ctrlless-serverless-apiserver \\
        --scheduler-stack ctrlless-serverless-lambda \\
        --ddb-table-prefix ctrlless-serverless-apiserver \\
        --worker-tag-project ctrlless-serverless \\
        --project-tag masters-thesis-lambda-ctrl \\
        --hours 2

    # A specific past window:
    python measure_cost.py \\
        --start 2026-04-23T14:00:00Z --end 2026-04-23T15:00:00Z

Resources covered
-----------------
    Lambda     - Invocations + Duration -> request + GB-s cost
    API GW     - REST API Count metric -> per-request cost
    DynamoDB   - Consumed RRU/WRU (table + GSIs) + storage proration
    SQS        - Sent / Received / EmptyReceives / Deleted -> request cost
    CW Logs    - IncomingBytes per log group (Lambda + API GW access logs)
    VPC        - Interface endpoints tagged with --project-tag -> ENI-hours
    EC2        - Kubelet worker instance-hours (by type) + gp3 EBS

Not covered (small for this stack, but edit if you care)
    - DynamoDB Streams read request units (no clean AWS/DynamoDB metric)
    - CloudWatch Logs storage (usually small vs ingestion)
    - Data transfer through VPC endpoints / NAT / inter-AZ
    - EC2 public IPv4 / data transfer / snapshots
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

    # API Gateway REST API (first 333M req/month tier)
    "apigw_rest_request":      3.50 / 1_000_000,

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

    # EBS gp3
    "ebs_gp3_gb_month":        0.08,
}

# EC2 on-demand Linux, us-east-1, per-hour. Extend as needed.
# Any type not listed falls back to --ec2-default-hourly.
EC2_HOURLY = {
    "t3.nano":    0.0052,
    "t3.micro":   0.0104,
    "t3.small":   0.0208,
    "t3.medium":  0.0416,
    "t3.large":   0.0832,
    "t3.xlarge":  0.1664,
    "t3.2xlarge": 0.3328,
    "t3a.large":  0.0752,
    "m5.large":   0.0960,
    "m5.xlarge":  0.1920,
    "m6i.large":  0.0960,
    "c6i.large":  0.0850,
    "c6i.xlarge": 0.1700,
}

HOURS_PER_MONTH = 730  # AWS billing convention: 24 * 365.25 / 12


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--apiserver-stack", default="ctrlless-serverless-apiserver",
                   help="CloudFormation stack for the Lambda apiserver")
    p.add_argument("--scheduler-stack", default="ctrlless-serverless-lambda",
                   help="CloudFormation stack for the scheduler/controllers")
    p.add_argument("--extra-stack", action="append", default=[],
                   help="Additional stack to include (repeatable)")
    p.add_argument("--ddb-table-prefix", default="ctrlless-serverless-apiserver",
                   help="DynamoDB table name prefix to include beyond stack "
                        "resources (apiserver tables are precreated outside SAM)")
    p.add_argument("--worker-tag-project", default="ctrlless-serverless",
                   help="Value of the Project tag on kubelet EC2 workers "
                        "(set by deploy_serverless_kubelet.sh via TAG_PREFIX)")
    p.add_argument("--worker-tag-role", default="serverless-worker",
                   help="Value of the Role tag on kubelet EC2 workers")
    p.add_argument("--project-tag", default="masters-thesis-lambda-ctrl",
                   help="Value of the Project tag on Lambda/SAM resources "
                        "(used to find VPC endpoints)")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--hours", type=float, default=1.0,
                   help="Window length ending now, in hours (default 1.0)")
    p.add_argument("--start", help="ISO-8601 start (overrides --hours)")
    p.add_argument("--end", help="ISO-8601 end (defaults to now)")
    p.add_argument("--ec2-default-hourly", type=float, default=0.0832,
                   help="Fallback EC2 per-hour price for unknown instance types")
    p.add_argument("--include-stopped-workers", action="store_true",
                   help="Charge stopped workers (EBS only) for their running time in window")
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
def discover_stack(cfn, stack_name: str):
    """Enumerate interesting resources in one stack. Missing stack -> empty."""
    funcs, tables, queues, apis = [], [], [], []
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
                elif t == "AWS::ApiGateway::RestApi":
                    apis.append(pid)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        msg = e.response.get("Error", {}).get("Message", str(e))
        if code == "ValidationError" and "does not exist" in msg:
            print(f"  [warn] stack '{stack_name}' not found — skipping", file=sys.stderr)
            return [], [], [], []
        raise
    return funcs, tables, queues, apis


def discover_ddb_by_prefix(ddb, prefix: str) -> list[str]:
    if not prefix:
        return []
    names = []
    pages = ddb.get_paginator("list_tables").paginate()
    for page in pages:
        names.extend(n for n in page["TableNames"] if n.startswith(prefix))
    return names


def discover_vpc_endpoints(ec2, project_tag: str):
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
    return endpoints


def discover_workers(ec2, project_tag: str, role_tag: str, include_stopped: bool):
    """Return per-instance dicts: id, type, state, launch_time, volumes (gb)."""
    states = ["running"] + (["stopped", "stopping"] if include_stopped else [])
    resp = ec2.describe_instances(Filters=[
        {"Name": "tag:Project", "Values": [project_tag]},
        {"Name": "tag:Role",    "Values": [role_tag]},
        {"Name": "instance-state-name", "Values": states},
    ])
    out = []
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            vol_gb = 0.0
            for bdm in inst.get("BlockDeviceMappings", []):
                ebs = bdm.get("Ebs") or {}
                vid = ebs.get("VolumeId")
                if not vid:
                    continue
                v = ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]
                vol_gb += v.get("Size", 0)
            name = ""
            for tag in inst.get("Tags", []) or []:
                if tag.get("Key") == "Name":
                    name = tag.get("Value", "")
                    break
            out.append({
                "id":          inst["InstanceId"],
                "name":        name,
                "type":        inst["InstanceType"],
                "state":       inst["State"]["Name"],
                "launch_time": inst["LaunchTime"],
                "ebs_gb":      vol_gb,
            })
    return out


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
        try:
            memory_mb = lam.get_function_configuration(FunctionName=f)["MemorySize"]
        except ClientError:
            memory_mb = 512
        gb_seconds = (duration_ms / 1000.0) * (memory_mb / 1024.0)
        cost = (invocations * PRICE["lambda_request"]
                + gb_seconds * PRICE["lambda_gb_second"])
        rows.append({
            "name": f, "invocations": int(invocations),
            "duration_s": duration_ms / 1000.0, "memory_mb": memory_mb,
            "gb_seconds": gb_seconds, "cost": cost,
        })
    return rows


def apigw_rows(cw, apigw, api_ids, start, end):
    """
    AWS/ApiGateway emits Count per (ApiName, Stage). We look up each REST API
    by id, discover its stages, and sum Count. Matches REST (not HTTP API v2).
    """
    rows = []
    for api_id in api_ids:
        try:
            api = apigw.get_rest_api(restApiId=api_id)
            api_name = api["name"]
            stages = apigw.get_stages(restApiId=api_id).get("item", [])
        except ClientError:
            continue
        total = 0.0
        stage_names = []
        for st in stages:
            stage = st["stageName"]
            stage_names.append(stage)
            total += cw_sum(cw, "AWS/ApiGateway", "Count",
                            {"ApiName": api_name, "Stage": stage}, start, end)
        rows.append({
            "name": f"{api_name} ({api_id})",
            "stages": ",".join(stage_names) or "(none)",
            "requests": int(total),
            "cost": total * PRICE["apigw_rest_request"],
        })
    return rows


def ddb_rows(cw, ddb, tables, start, end):
    rows = []
    hours = (end - start).total_seconds() / 3600.0
    for t in tables:
        try:
            desc = ddb.describe_table(TableName=t)["Table"]
        except ClientError:
            continue

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


def logs_rows(cw, log_groups, start, end):
    rows = []
    for lg in sorted(set(log_groups)):
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


def ec2_rows(workers, start, end, default_hourly):
    """
    Charge each worker for the intersection of [start, end] with its lifetime
    (launch_time -> now, approximately). Stopped instances are billed EBS-only.
    """
    rows = []
    hours_window = (end - start).total_seconds() / 3600.0
    for w in workers:
        live_start = max(start, w["launch_time"])
        live_hours = max(0.0, (end - live_start).total_seconds() / 3600.0)
        inst_hourly = EC2_HOURLY.get(w["type"], default_hourly)
        known = w["type"] in EC2_HOURLY
        inst_cost = (live_hours * inst_hourly) if w["state"] == "running" else 0.0
        ebs_cost = (w["ebs_gb"] * PRICE["ebs_gp3_gb_month"]
                    * (hours_window / HOURS_PER_MONTH))
        rows.append({
            "name":       f"{w['name'] or w['id']} ({w['id']})",
            "type":       w["type"] + ("" if known else "*"),
            "state":      w["state"],
            "hours":      live_hours,
            "ebs_gb":     w["ebs_gb"],
            "inst_cost":  inst_cost,
            "ebs_cost":   ebs_cost,
            "cost":       inst_cost + ebs_cost,
        })
    return rows


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
            if key.endswith("cost"):
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
    print(f"Region: {args.region}")
    print(f"Stacks: apiserver={args.apiserver_stack}  scheduler={args.scheduler_stack}"
          + (f"  extra={args.extra_stack}" if args.extra_stack else ""))
    print(f"DDB prefix: {args.ddb_table_prefix}   "
          f"Worker tags: Project={args.worker_tag_project}, Role={args.worker_tag_role}")
    print(f"Project tag (VPCE): {args.project_tag}")

    session = boto3.Session(region_name=args.region)
    cfn   = session.client("cloudformation")
    ec2   = session.client("ec2")
    cw    = session.client("cloudwatch")
    lam   = session.client("lambda")
    ddb   = session.client("dynamodb")
    apigw = session.client("apigateway")

    # Aggregate resources across all stacks (dedup on name).
    funcs, tables, queues, apis = [], [], [], []
    for stack in [args.apiserver_stack, args.scheduler_stack, *args.extra_stack]:
        if not stack:
            continue
        f, t, q, a = discover_stack(cfn, stack)
        funcs.extend(f); tables.extend(t); queues.extend(q); apis.extend(a)
    funcs  = sorted(set(funcs))
    queues = sorted(set(queues))
    apis   = sorted(set(apis))

    # Precreated apiserver tables live outside the stack — union by prefix.
    tables = sorted(set(tables) | set(discover_ddb_by_prefix(ddb, args.ddb_table_prefix)))

    endpoints = discover_vpc_endpoints(ec2, args.project_tag)
    workers   = discover_workers(ec2, args.worker_tag_project, args.worker_tag_role,
                                 args.include_stopped_workers)

    # Log groups: per-Lambda + per-API-Gateway access log group (if enabled)
    log_groups = [f"/aws/lambda/{f}" for f in funcs]
    log_groups += [f"API-Gateway-Execution-Logs_{a}/Prod" for a in apis]

    lam_r   = lambda_rows(cw, lam, funcs, start, end)
    api_r   = apigw_rows(cw, apigw, apis, start, end)
    ddb_r   = ddb_rows(cw, ddb, tables, start, end)
    sqs_r   = sqs_rows(cw, queues, start, end)
    logs_r  = logs_rows(cw, log_groups, start, end)
    vpce_r  = vpce_rows(endpoints, start, end)
    ec2_r   = ec2_rows(workers, start, end, args.ec2_default_hourly)

    # --- Core serverless sections (headline cost) ---
    print_section("Lambda",        lam_r,
                  [("name", 52), ("invocations", 11), ("duration_s", 10),
                   ("gb_seconds", 10), ("cost", 12)])
    print_section("API Gateway",   api_r,
                  [("name", 52), ("stages", 12), ("requests", 10), ("cost", 12)])
    print_section("DynamoDB",      ddb_r,
                  [("name", 52), ("rru", 12), ("wru", 12),
                   ("size_gb", 9), ("cost", 12)])
    print_section("SQS",           sqs_r,
                  [("name", 52), ("sent", 8), ("received", 9),
                   ("empty", 8), ("deleted", 8), ("cost", 12)])

    core_total = sum(r["cost"] for rs in (lam_r, api_r, ddb_r, sqs_r) for r in rs)
    core_hourly  = core_total / hours
    core_monthly = core_hourly * HOURS_PER_MONTH

    print()
    print("  ========== Serverless core (Lambda + API GW + DynamoDB + SQS) ==========")
    print(f"  Window total:                  ${core_total:12.6f}")
    print(f"  Projected hourly:              ${core_hourly:12.6f}")
    print(f"  Projected monthly (x{HOURS_PER_MONTH}):        ${core_monthly:12.2f}")

    # --- Supplementary sections (reported separately, not in core) ---
    print_section("CW Logs",       logs_r,
                  [("name", 52), ("bytes", 12), ("gb", 9), ("cost", 12)])
    print_section("VPC Endpoints", vpce_r,
                  [("name", 52), ("eni_count", 10), ("eni_hours", 11), ("cost", 12)])
    print_section("EC2 Workers",   ec2_r,
                  [("name", 46), ("type", 12), ("state", 8), ("hours", 8),
                   ("ebs_gb", 7), ("inst_cost", 11), ("ebs_cost", 11),
                   ("cost", 12)])

    logs_total = sum(r["cost"] for r in logs_r)
    vpce_total = sum(r["cost"] for r in vpce_r)
    ec2_total  = sum(r["cost"] for r in ec2_r)
    all_total  = core_total + logs_total + vpce_total + ec2_total
    all_hourly  = all_total / hours
    all_monthly = all_hourly * HOURS_PER_MONTH

    print()
    print("  ========== All-in (core + logs + VPC + EC2 workers) ==========")
    print(f"    CW Logs:                     ${logs_total:12.6f}")
    print(f"    VPC Endpoints:               ${vpce_total:12.6f}")
    print(f"    EC2 Workers:                 ${ec2_total:12.6f}")
    print(f"  Window total:                  ${all_total:12.6f}")
    print(f"  Projected hourly:              ${all_hourly:12.6f}")
    print(f"  Projected monthly (x{HOURS_PER_MONTH}):        ${all_monthly:12.2f}")
    print()
    print("  Prices: us-east-1 list, pre-Free-Tier, pre-Savings-Plans.")
    print("  '*' after an EC2 type = price not in table, --ec2-default-hourly used.")
    print("  Edit PRICE{} / EC2_HOURLY at the top of this file for your region.")


if __name__ == "__main__":
    main()
