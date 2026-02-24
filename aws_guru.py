#!/usr/bin/env python3
# Copyright 2026 Christopher Grigor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
aws_guru - AWS inventory & monitoring CLI

Scans common AWS resource types across all configured regions and prints
an HTML table per resource type.  Includes a dedicated monitoring checker
that audits CloudWatch, CloudTrail, Config, GuardDuty, Security Hub, and
EventBridge for every region.
"""

import contextlib
import io
import os
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Any

import boto3
from botocore.exceptions import ClientError, EndpointResolutionError
from tabulate import tabulate


# ---------------------------------------------------------------------------
# Output context — set to True via --md flag to emit Markdown + save file
# ---------------------------------------------------------------------------
_MD_MODE: bool = False


# ---------------------------------------------------------------------------
# Monitoring findings collector
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_OK       = "OK"

_SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH:     1,
    SEVERITY_MEDIUM:   2,
    SEVERITY_LOW:      3,
    SEVERITY_OK:       4,
}

_SEVERITY_ICON = {
    SEVERITY_CRITICAL: "🔴",
    SEVERITY_HIGH:     "🟠",
    SEVERITY_MEDIUM:   "🟡",
    SEVERITY_LOW:      "🔵",
    SEVERITY_OK:       "🟢",
}


@dataclass
class Finding:
    severity: str
    region: str
    service: str
    title: str
    detail: str
    recommendation: str


@dataclass
class MonitoringState:
    """Accumulated findings from all monitoring checks across all regions."""
    findings: list[Finding] = field(default_factory=list)

    # Per-region raw counts for the summary table
    region_stats: dict[str, dict] = field(default_factory=dict)

    def add(
        self,
        severity: str,
        region: str,
        service: str,
        title: str,
        detail: str,
        recommendation: str,
    ) -> None:
        self.findings.append(Finding(severity, region, service, title, detail, recommendation))

    def ok(self, region: str, service: str, title: str, detail: str = "") -> None:
        self.findings.append(Finding(SEVERITY_OK, region, service, title, detail, ""))

    def record_region_stat(self, region: str, key: str, value: Any) -> None:
        self.region_stats.setdefault(region, {})[key] = value


# ---------------------------------------------------------------------------
# Regions to scan
# ---------------------------------------------------------------------------
REGIONS: list[str] = [
    "eu-west-1",
    "us-east-1",
    "us-west-2",
    "us-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "sa-east-1",
]


# ---------------------------------------------------------------------------
# Signal handler
# ---------------------------------------------------------------------------
def signal_handler(sig: int, frame: Any) -> None:
    print("\n\nYOU CAN HAZ CTRL+C!\n\n")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ---------------------------------------------------------------------------
# Tag helpers
# ---------------------------------------------------------------------------
def _find_tag(tag_list: list[dict], key: str, name: str) -> str:
    try:
        for tag in tag_list:
            if tag["Key"] == name:
                return tag["Value"]
    except (KeyError, TypeError):
        pass
    return ""


def get_tags(obj: dict, name: str) -> str:
    for key in ("Tags", "TagSet", "TagList"):
        val = _find_tag(obj.get(key, []), key, name)
        if val:
            return val
    return ""


def elb_get_tags(conn: Any, lb_name: str, tag: str) -> str:
    try:
        resp = conn.describe_tags(LoadBalancerNames=[lb_name])
        return get_tags(resp["TagDescriptions"][0], tag)
    except (ClientError, KeyError, IndexError):
        return ""


def elb_get_arn_tag(conn: Any, arn: str, tag: str) -> str:
    try:
        resp = conn.describe_tags(ResourceArns=[arn])
        return get_tags(resp["TagDescriptions"][0], tag)
    except (ClientError, KeyError, IndexError):
        return ""


def s3_get_tags(conn: Any, bucket: str, tag: str) -> str:
    try:
        resp = conn.get_bucket_tagging(Bucket=bucket)
        return get_tags(resp, tag)
    except ClientError:
        return ""


def elasticache_get_tags(conn: Any, arn: str, tag: str) -> str:
    try:
        resp = conn.list_tags_for_resource(ResourceName=arn)
        return get_tags(resp, tag)
    except ClientError:
        return ""


# ---------------------------------------------------------------------------
# Core display helpers
# ---------------------------------------------------------------------------
def print_result(title: str, table: list, headers: tuple = ()) -> None:
    if not table:
        return
    if _MD_MODE:
        print(f"\n### {title}\n")
        print(tabulate(table, headers, tablefmt="github"))
    else:
        print(f"\n=== {title} ===\n")
        print(tabulate(table, headers, tablefmt="html"))


def get_property_func(key: str) -> Callable:
    aliases = {
        "ip": "ip_address",
        "private_ip": "private_ip_address",
    }
    real_key = aliases.get(key, key)

    def getter(obj: Any) -> Any:
        try:
            return getattr(obj, real_key)
        except AttributeError:
            if isinstance(obj, dict):
                if key == "name":
                    return get_tags(obj, "Name")
                return obj.get(real_key) or get_tags(obj, key)
            tags = getattr(obj, "tags", {})
            return tags.get("Name") if key == "name" else tags.get(key)

    return getter


def filter_key(filter_args: dict) -> Callable:
    def match(obj: Any) -> bool:
        return all(
            value == get_property_func(k)(obj) for k, value in filter_args.items()
        )

    return match


def voyeur(
    instances: list,
    to_row: Callable,
    sort_by: str | None = None,
    filter_by: dict | None = None,
) -> list:
    if sort_by:
        instances = sorted(instances, key=get_property_func(sort_by))
    if filter_by:
        instances = [i for i in instances if filter_key(filter_by)(i)]
    return [to_row(i) for i in instances]


def get_options(
    input_args: list[str], headers: tuple = ()
) -> tuple[str | None, dict]:
    sort_by = None
    filter_kwargs: dict = {}
    for arg in input_args:
        if arg.startswith("-"):
            continue
        if "=" in arg:
            key, value = arg.split("=", 1)
            if key not in headers:
                sys.exit(f"{key!r} is not a valid header. Choose from: {headers}")
            filter_kwargs[key] = value
        elif arg in headers:
            sort_by = arg
        else:
            print("skipped:", arg)
    return sort_by, filter_kwargs


# ---------------------------------------------------------------------------
# Pagination helper
# ---------------------------------------------------------------------------
def paginate(client: Any, method: str, result_key: str, **kwargs: Any) -> list:
    """Collect all pages for a boto3 paginated API call."""
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(result_key, []))
    return results


# ---------------------------------------------------------------------------
# Resource checkers
# ---------------------------------------------------------------------------
def list_ec2(input_args: list[str]) -> None:
    headers = ("name", "customer", "environment", "ip", "private_ip", "launch_time", "id")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("ec2", region_name=region)
        try:
            reservations = paginate(conn, "describe_instances", "Reservations")
            instances = [i for r in reservations for i in r.get("Instances", [])]
        except ClientError as exc:
            print(f"[ec2] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                get_tags(x, "Name"),
                get_tags(x, "Customer"),
                get_tags(x, "Environment"),
                x.get("PublicIpAddress", ""),
                x.get("PrivateIpAddress", ""),
                x.get("LaunchTime", ""),
                x.get("InstanceId", ""),
            )

        print_result(
            f"EC2 @ region '{region}'",
            voyeur(instances, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_elb(input_args: list[str]) -> None:
    headers = ("name", "customer", "environment", "created_time")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("elb", region_name=region)
        try:
            lbs = paginate(conn, "describe_load_balancers", "LoadBalancerDescriptions")
        except ClientError as exc:
            print(f"[elb] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["LoadBalancerName"],
                elb_get_tags(conn, x["LoadBalancerName"], "Customer"),
                elb_get_tags(conn, x["LoadBalancerName"], "Environment"),
                x.get("CreatedTime", ""),
            )

        print_result(
            f"EC2:ELB @ region '{region}'",
            voyeur(lbs, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_elbv2(input_args: list[str]) -> None:
    headers = ("name", "customer", "environment", "created_time")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("elbv2", region_name=region)
        try:
            lbs = paginate(conn, "describe_load_balancers", "LoadBalancers")
        except ClientError as exc:
            print(f"[elbv2] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["LoadBalancerArn"],
                elb_get_arn_tag(conn, x["LoadBalancerArn"], "Customer"),
                elb_get_arn_tag(conn, x["LoadBalancerArn"], "Environment"),
                x.get("CreatedTime", ""),
            )

        print_result(
            f"EC2:ALB @ region '{region}'",
            voyeur(lbs, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_rds(input_args: list[str]) -> None:
    headers = ("id", "engine", "status", "endpoint", "environment")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("rds", region_name=region)
        try:
            instances = paginate(conn, "describe_db_instances", "DBInstances")
        except ClientError as exc:
            print(f"[rds] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            ep = x.get("Endpoint", {})
            host = ep.get("Address", "")
            port = ep.get("Port", "")
            db = x.get("DBName", "")
            uri = f"{x.get('Engine','')}://{x.get('MasterUsername','')}@{host}:{port}/{db}"
            return (
                x["DBInstanceIdentifier"],
                x.get("Engine", ""),
                x.get("DBInstanceStatus", ""),
                uri,
                get_tags(x, "Environment"),
            )

        print_result(
            f"RDS @ region '{region}'",
            voyeur(instances, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_elasticache(input_args: list[str]) -> None:
    headers = ("cluster id", "engine", "status", "environment", "created_time")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("elasticache", region_name=region)
        try:
            clusters = paginate(conn, "describe_cache_clusters", "CacheClusters")
        except ClientError as exc:
            print(f"[elasticache] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            arn = f"arn:aws:elasticache:{region}::cluster:{x['CacheClusterId']}"
            return (
                x["CacheClusterId"],
                x.get("Engine", ""),
                x.get("CacheClusterStatus", ""),
                elasticache_get_tags(conn, arn, "Environment"),
                x.get("CacheClusterCreateTime", ""),
            )

        print_result(
            f"ElastiCache @ region '{region}'",
            voyeur(clusters, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_vpc(input_args: list[str]) -> None:
    headers = ("id", "name", "environment", "cidr_block")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("ec2", region_name=region)
        try:
            vpcs = conn.describe_vpcs()["Vpcs"]
        except ClientError as exc:
            print(f"[vpc] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["VpcId"],
                get_tags(x, "Name"),
                get_tags(x, "Environment"),
                x["CidrBlock"],
            )

        print_result(
            f"VPC @ region '{region}'",
            voyeur(vpcs, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_sg(input_args: list[str]) -> None:
    headers = ("id", "group_name", "name", "environment")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("ec2", region_name=region)
        try:
            sgs = paginate(conn, "describe_security_groups", "SecurityGroups")
        except ClientError as exc:
            print(f"[sg] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["GroupId"],
                x["GroupName"],
                get_tags(x, "Name"),
                get_tags(x, "Environment"),
            )

        print_result(
            f"EC2:SG @ region '{region}'",
            voyeur(sgs, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_eks(input_args: list[str]) -> None:
    headers = (
        "name",
        "version",
        "status",
        "endpoint",
        "environment",
        "created_at",
    )
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("eks", region_name=region)
        try:
            cluster_names = paginate(conn, "list_clusters", "clusters")
        except ClientError as exc:
            print(f"[eks] {region}: {exc}")
            continue

        clusters = []
        for name in cluster_names:
            try:
                clusters.append(conn.describe_cluster(name=name)["cluster"])
            except ClientError as exc:
                print(f"[eks] {region} describe {name}: {exc}")

        def to_row(x: dict) -> tuple:
            return (
                x["name"],
                x.get("version", ""),
                x.get("status", ""),
                x.get("endpoint", ""),
                get_tags(x, "Environment"),
                x.get("createdAt", ""),
            )

        print_result(
            f"EKS:Clusters @ region '{region}'",
            voyeur(clusters, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )

        # Node groups for each cluster
        ng_headers = ("cluster", "nodegroup", "status", "instance_type", "min", "desired", "max", "version")
        ng_rows = []
        for cluster in clusters:
            try:
                ng_names = paginate(conn, "list_nodegroups", "nodegroups", clusterName=cluster["name"])
                for ng_name in ng_names:
                    ng = conn.describe_nodegroup(clusterName=cluster["name"], nodegroupName=ng_name)["nodegroup"]
                    scaling = ng.get("scalingConfig", {})
                    instance_types = ", ".join(ng.get("instanceTypes", []))
                    ng_rows.append((
                        cluster["name"],
                        ng["nodegroupName"],
                        ng.get("status", ""),
                        instance_types,
                        scaling.get("minSize", ""),
                        scaling.get("desiredSize", ""),
                        scaling.get("maxSize", ""),
                        ng.get("version", ""),
                    ))
            except ClientError as exc:
                print(f"[eks] {region} nodegroups {cluster['name']}: {exc}")

        print_result(
            f"EKS:NodeGroups @ region '{region}'",
            ng_rows,
            ng_headers,
        )

        # Fargate profiles for each cluster
        fp_headers = ("cluster", "profile", "status", "namespace_selectors")
        fp_rows = []
        for cluster in clusters:
            try:
                fp_names = paginate(conn, "list_fargate_profiles", "fargateProfileNames", clusterName=cluster["name"])
                for fp_name in fp_names:
                    fp = conn.describe_fargate_profile(clusterName=cluster["name"], fargateProfileName=fp_name)["fargateProfile"]
                    selectors = "; ".join(
                        f"{s.get('namespace', '')}:{','.join(f'{k}={v}' for k, v in s.get('labels', {}).items())}"
                        for s in fp.get("selectors", [])
                    )
                    fp_rows.append((
                        cluster["name"],
                        fp["fargateProfileName"],
                        fp.get("status", ""),
                        selectors,
                    ))
            except ClientError as exc:
                print(f"[eks] {region} fargate {cluster['name']}: {exc}")

        print_result(
            f"EKS:FargateProfiles @ region '{region}'",
            fp_rows,
            fp_headers,
        )


def list_volume(input_args: list[str]) -> None:
    headers = ("id", "size", "status", "created_time")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("ec2", region_name=region)
        try:
            vols = paginate(conn, "describe_volumes", "Volumes")
        except ClientError as exc:
            print(f"[volume] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["VolumeId"],
                x.get("Size", ""),
                x.get("State", ""),
                x.get("CreateTime", ""),
            )

        print_result(
            f"EC2:Volumes @ region '{region}'",
            voyeur(vols, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_dbss(input_args: list[str]) -> None:
    headers = ("SS id", "DB id", "engine", "create time")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("rds", region_name=region)
        try:
            snaps = paginate(conn, "describe_db_snapshots", "DBSnapshots")
        except ClientError as exc:
            print(f"[dbss] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["DBSnapshotIdentifier"],
                x["DBInstanceIdentifier"],
                x.get("Engine", ""),
                x.get("SnapshotCreateTime", ""),
            )

        print_result(
            f"RDS:Snapshots @ region '{region}'",
            voyeur(snaps, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_ec2ss(input_args: list[str]) -> None:
    headers = ("SS id", "state", "environment", "size", "create time")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("ec2", region_name=region)
        try:
            snaps = paginate(conn, "describe_snapshots", "Snapshots", OwnerIds=["self"])
        except ClientError as exc:
            print(f"[ec2ss] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["SnapshotId"],
                x.get("State", ""),
                get_tags(x, "Environment"),
                x.get("VolumeSize", ""),
                x.get("StartTime", ""),
            )

        print_result(
            f"EC2:Snapshots @ region '{region}'",
            voyeur(snaps, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_ecss(input_args: list[str]) -> None:
    headers = ("SS name", "state", "source")
    sort_by, filter_by = get_options(input_args, headers)

    for region in REGIONS:
        conn = boto3.client("elasticache", region_name=region)
        try:
            snaps = paginate(conn, "describe_snapshots", "Snapshots")
        except ClientError as exc:
            print(f"[ecss] {region}: {exc}")
            continue

        def to_row(x: dict) -> tuple:
            return (
                x["SnapshotName"],
                x.get("SnapshotStatus", ""),
                x.get("SnapshotSource", ""),
            )

        print_result(
            f"ElastiCache:Snapshots @ region '{region}'",
            voyeur(snaps, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
            headers,
        )


def list_s3(input_args: list[str]) -> None:
    headers = ("name", "region", "environment", "created_time")
    sort_by, filter_by = get_options(input_args, headers)

    conn = boto3.client("s3")
    try:
        buckets = conn.list_buckets()["Buckets"]
    except ClientError as exc:
        print(f"[s3]: {exc}")
        return

    def to_row(x: dict) -> tuple:
        try:
            loc = conn.get_bucket_location(Bucket=x["Name"])["LocationConstraint"]
            region = (loc or "us-east-1").replace("EU", "eu-west-1")
        except ClientError:
            region = "unknown"
        return (
            x["Name"],
            region,
            s3_get_tags(conn, x["Name"], "Environment"),
            x.get("CreationDate", ""),
        )

    print_result(
        "S3 @ 'worldwide'",
        voyeur(buckets, to_row=to_row, sort_by=sort_by, filter_by=filter_by),
        headers,
    )


# ---------------------------------------------------------------------------
# Monitoring sub-checkers (one function per service)
# Each accepts the region string and a MonitoringState collector.
# ---------------------------------------------------------------------------

def _check_cloudwatch(region: str, state: MonitoringState) -> None:
    try:
        cw = boto3.client("cloudwatch", region_name=region)
        alarms = paginate(cw, "describe_alarms", "MetricAlarms")
        comp_alarms = paginate(cw, "describe_alarms", "CompositeAlarms")

        alarm_rows = [
            (
                a["AlarmName"],
                a.get("AlarmDescription", ""),
                a.get("StateValue", ""),
                a.get("MetricName", ""),
                a.get("Namespace", ""),
            )
            for a in alarms
        ]
        comp_rows = [
            (a["AlarmName"], a.get("AlarmDescription", ""), a.get("StateValue", ""), "composite", "")
            for a in comp_alarms
        ]
        all_alarm_rows = alarm_rows + comp_rows

        print_result(
            f"CloudWatch:Alarms @ '{region}'",
            all_alarm_rows,
            ("name", "description", "state", "metric", "namespace"),
        )

        state.record_region_stat(region, "cw_alarm_count", len(all_alarm_rows))

        if not all_alarm_rows:
            print(f"  [!] NO CloudWatch alarms found in {region}")
            state.add(
                SEVERITY_HIGH, region, "CloudWatch",
                "No alarms configured",
                "No metric alarms or composite alarms exist in this region.",
                "Create alarms for key metrics: CPU utilisation, error rates, "
                "4xx/5xx rates on load balancers, RDS storage, Lambda errors, "
                "and any business-critical custom metrics.",
            )
        else:
            in_alarm = [a for a in alarms if a.get("StateValue") == "ALARM"]
            no_desc  = [a for a in alarms if not a.get("AlarmDescription", "").strip()]
            if in_alarm:
                state.add(
                    SEVERITY_HIGH, region, "CloudWatch",
                    f"{len(in_alarm)} alarm(s) currently in ALARM state",
                    ", ".join(a["AlarmName"] for a in in_alarm),
                    "Investigate and resolve the active alarms. Ensure SNS topics "
                    "are configured so on-call teams receive notifications.",
                )
            if no_desc:
                state.add(
                    SEVERITY_LOW, region, "CloudWatch",
                    f"{len(no_desc)} alarm(s) have no description",
                    ", ".join(a["AlarmName"] for a in no_desc[:10]),
                    "Add descriptions to all alarms so responders understand "
                    "the purpose and impact without needing to read the metric definition.",
                )
            else:
                state.ok(region, "CloudWatch", f"{len(all_alarm_rows)} alarm(s) configured")

        dash_resp = cw.list_dashboards()
        dashboards = dash_resp.get("DashboardEntries", [])
        while dash_resp.get("NextToken"):
            dash_resp = cw.list_dashboards(NextToken=dash_resp["NextToken"])
            dashboards.extend(dash_resp.get("DashboardEntries", []))

        dash_rows = [
            (d["DashboardName"], d.get("LastModified", ""), d.get("Size", ""))
            for d in dashboards
        ]
        print_result(
            f"CloudWatch:Dashboards @ '{region}'",
            dash_rows,
            ("name", "last_modified", "size_bytes"),
        )

        if not dash_rows:
            print(f"  [!] No CloudWatch dashboards in {region}")
            state.add(
                SEVERITY_LOW, region, "CloudWatch",
                "No dashboards",
                "No CloudWatch dashboards found in this region.",
                "Create dashboards for each service tier (compute, database, network) "
                "to give operators a single-pane-of-glass view during incidents.",
            )
        else:
            state.ok(region, "CloudWatch", f"{len(dash_rows)} dashboard(s) present")

    except ClientError as exc:
        print(f"  [cloudwatch] {region}: {exc}")


def _check_cloudwatch_logs(region: str, state: MonitoringState) -> None:
    try:
        logs = boto3.client("logs", region_name=region)
        log_groups = paginate(logs, "describe_log_groups", "logGroups")

        lg_rows = [
            (
                lg["logGroupName"],
                lg.get("retentionInDays", "never expires"),
                lg.get("storedBytes", 0),
            )
            for lg in log_groups
        ]
        print_result(
            f"CloudWatch:LogGroups @ '{region}'",
            lg_rows,
            ("log_group", "retention_days", "stored_bytes"),
        )

        state.record_region_stat(region, "log_group_count", len(log_groups))

        if not log_groups:
            print(f"  [!] No CloudWatch Log Groups in {region}")
            state.add(
                SEVERITY_MEDIUM, region, "CloudWatch Logs",
                "No log groups",
                "No CloudWatch Log Groups exist in this region.",
                "Ensure application logs, VPC Flow Logs, and CloudTrail logs are "
                "shipped to CloudWatch Logs for centralised querying and alerting.",
            )
        else:
            no_retention = [
                lg["logGroupName"] for lg in log_groups
                if "retentionInDays" not in lg
            ]
            if no_retention:
                state.add(
                    SEVERITY_MEDIUM, region, "CloudWatch Logs",
                    f"{len(no_retention)} log group(s) have no retention policy",
                    ", ".join(no_retention[:10]) + ("…" if len(no_retention) > 10 else ""),
                    "Set a retention policy (e.g. 90 or 365 days) on all log groups "
                    "to control storage costs and meet data-retention compliance requirements.",
                )
            else:
                state.ok(region, "CloudWatch Logs", "All log groups have retention policies")

        metric_filters = paginate(logs, "describe_metric_filters", "metricFilters")
        mf_rows = [
            (
                mf.get("logGroupName", ""),
                mf["filterName"],
                mf.get("filterPattern", ""),
                ", ".join(t.get("metricName", "") for t in mf.get("metricTransformations", [])),
            )
            for mf in metric_filters
        ]
        print_result(
            f"CloudWatch:MetricFilters @ '{region}'",
            mf_rows,
            ("log_group", "filter_name", "pattern", "metrics"),
        )

        state.record_region_stat(region, "metric_filter_count", len(metric_filters))

        if not metric_filters:
            state.add(
                SEVERITY_MEDIUM, region, "CloudWatch Logs",
                "No metric filters defined",
                "No metric filters found — log-based alerting is not in use.",
                "Add metric filters for critical log patterns such as ERROR/FATAL "
                "messages, authentication failures, and security group changes, "
                "then attach CloudWatch Alarms to the resulting metrics.",
            )
        else:
            state.ok(region, "CloudWatch Logs", f"{len(metric_filters)} metric filter(s) active")

    except ClientError as exc:
        print(f"  [cloudwatch-logs] {region}: {exc}")


def _check_cloudtrail(region: str, state: MonitoringState) -> None:
    try:
        ct = boto3.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        trail_rows = []

        for trail in trails:
            status_resp = ct.get_trail_status(Name=trail["TrailARN"])
            is_logging   = bool(status_resp.get("IsLogging"))
            is_multi     = bool(trail.get("IsMultiRegionTrail"))
            has_cw_logs  = bool(trail.get("CloudWatchLogsLogGroupArn"))
            has_insights = bool(trail.get("HasInsightSelectors"))

            trail_rows.append((
                trail["Name"],
                trail["TrailARN"],
                "Yes" if is_multi    else "No",
                "Yes" if is_logging  else "NO ⚠️",
                trail.get("S3BucketName", ""),
                "Yes" if has_cw_logs else "No",
            ))

            if not is_logging:
                state.add(
                    SEVERITY_CRITICAL, region, "CloudTrail",
                    f"Trail '{trail['Name']}' is NOT logging",
                    "CloudTrail is configured but logging is disabled — API activity is not being recorded.",
                    "Run: aws cloudtrail start-logging --name <trail-arn>  "
                    "and investigate why logging was stopped.",
                )
            else:
                if not is_multi:
                    state.add(
                        SEVERITY_MEDIUM, region, "CloudTrail",
                        f"Trail '{trail['Name']}' is single-region only",
                        "Activity in other regions will not be captured by this trail.",
                        "Enable multi-region trail so all API activity across all regions "
                        "is recorded to a single S3 bucket.",
                    )
                if not has_cw_logs:
                    state.add(
                        SEVERITY_MEDIUM, region, "CloudTrail",
                        f"Trail '{trail['Name']}' is not integrated with CloudWatch Logs",
                        "CloudTrail events are written to S3 only — real-time alerting on API activity is not possible.",
                        "Configure a CloudWatch Logs log group on the trail to enable "
                        "metric filters and alarms for suspicious API calls (e.g. root login, "
                        "IAM changes, security group modifications).",
                    )
                else:
                    state.ok(region, "CloudTrail",
                             f"Trail '{trail['Name']}' logging + CW Logs integration active")

        print_result(
            f"CloudTrail:Trails @ '{region}'",
            trail_rows,
            ("name", "arn", "multi_region", "is_logging", "s3_bucket", "cw_logs"),
        )

        state.record_region_stat(region, "trail_count", len(trails))

        if not trails:
            print(f"  [!] NO CloudTrail trails found in {region}")
            state.add(
                SEVERITY_CRITICAL, region, "CloudTrail",
                "No CloudTrail trails",
                "No API activity is being recorded in this region.",
                "Create a CloudTrail trail (ideally multi-region) with S3 delivery, "
                "CloudWatch Logs integration, and log file validation enabled. "
                "This is a prerequisite for almost all security incident response.",
            )

    except ClientError as exc:
        print(f"  [cloudtrail] {region}: {exc}")


def _check_config(region: str, state: MonitoringState) -> None:
    try:
        cfg = boto3.client("config", region_name=region)
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        rec_statuses = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
        status_map = {s["name"]: s for s in rec_statuses}
        rec_rows = [
            (
                r["name"],
                r.get("roleARN", ""),
                "Yes" if status_map.get(r["name"], {}).get("recording") else "NO ⚠️",
                status_map.get(r["name"], {}).get("lastStatus", ""),
            )
            for r in recorders
        ]
        print_result(
            f"Config:Recorders @ '{region}'",
            rec_rows,
            ("name", "role_arn", "recording", "last_status"),
        )

        state.record_region_stat(region, "config_recorder_count", len(recorders))

        if not recorders:
            print(f"  [!] No AWS Config recorders in {region}")
            state.add(
                SEVERITY_HIGH, region, "AWS Config",
                "Config recorder not set up",
                "AWS Config is not recording resource configuration changes in this region.",
                "Enable AWS Config with a recorder covering all resource types. "
                "This is required for change tracking, compliance auditing, and many "
                "Security Hub controls.",
            )
        else:
            for r in recorders:
                if not status_map.get(r["name"], {}).get("recording"):
                    state.add(
                        SEVERITY_HIGH, region, "AWS Config",
                        f"Config recorder '{r['name']}' exists but is NOT recording",
                        "The recorder is configured but paused.",
                        "Start the recorder: aws configservice start-configuration-recorder "
                        f"--configuration-recorder-name {r['name']}",
                    )
                else:
                    state.ok(region, "AWS Config", f"Recorder '{r['name']}' is active")

        rules = paginate(cfg, "describe_config_rules", "ConfigRules")
        rule_rows = [
            (
                r["ConfigRuleName"],
                r.get("Source", {}).get("SourceIdentifier", ""),
                r.get("ConfigRuleState", ""),
            )
            for r in rules
        ]
        print_result(
            f"Config:Rules @ '{region}'",
            rule_rows,
            ("rule_name", "source", "state"),
        )

        state.record_region_stat(region, "config_rule_count", len(rules))

        if not rules:
            print(f"  [!] No AWS Config rules in {region}")
            state.add(
                SEVERITY_MEDIUM, region, "AWS Config",
                "No Config rules defined",
                "No compliance rules are evaluating resources in this region.",
                "Enable AWS managed rules for common controls: "
                "s3-bucket-public-read-prohibited, restricted-ssh, "
                "root-account-mfa-enabled, encrypted-volumes, "
                "rds-storage-encrypted, iam-password-policy, etc.",
            )
        else:
            state.ok(region, "AWS Config", f"{len(rules)} rule(s) defined")

    except ClientError as exc:
        print(f"  [config] {region}: {exc}")


def _check_guardduty(region: str, state: MonitoringState) -> None:
    try:
        gd = boto3.client("guardduty", region_name=region)
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        gd_rows = []

        for det_id in detector_ids:
            det = gd.get_detector(DetectorId=det_id)
            finding_count = gd.get_findings_statistics(
                DetectorId=det_id,
                FindingStatisticTypes=["COUNT_BY_SEVERITY"],
                FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
            ).get("FindingStatistics", {}).get("CountBySeverity", {})

            total_findings = sum(finding_count.values()) if finding_count else 0
            high_findings  = sum(v for k, v in finding_count.items() if float(k) >= 7.0) if finding_count else 0

            gd_rows.append((
                det_id,
                det.get("Status", ""),
                det.get("FindingPublishingFrequency", ""),
                det.get("UpdatedAt", ""),
                str(total_findings),
            ))

            freq = det.get("FindingPublishingFrequency", "")
            if freq == "SIX_HOURS":
                state.add(
                    SEVERITY_MEDIUM, region, "GuardDuty",
                    "Finding publish frequency is SIX_HOURS",
                    f"Detector {det_id} publishes findings every 6 hours.",
                    "Change FindingPublishingFrequency to FIFTEEN_MINUTES so security "
                    "teams are notified quickly. High-severity findings are always "
                    "published within 5 minutes regardless of this setting.",
                )
            if high_findings > 0:
                state.add(
                    SEVERITY_HIGH, region, "GuardDuty",
                    f"{high_findings} high/critical finding(s) active",
                    f"Detector {det_id} has {high_findings} unarchived findings with severity ≥7.",
                    "Review and triage GuardDuty findings immediately. High-severity findings "
                    "indicate likely compromised credentials, C2 activity, or crypto-mining.",
                )
            elif total_findings > 0:
                state.add(
                    SEVERITY_MEDIUM, region, "GuardDuty",
                    f"{total_findings} active finding(s)",
                    f"Detector {det_id} has {total_findings} unarchived findings.",
                    "Review and triage all open GuardDuty findings.",
                )
            else:
                state.ok(region, "GuardDuty", f"Detector {det_id} enabled, no active findings")

        print_result(
            f"GuardDuty:Detectors @ '{region}'",
            gd_rows,
            ("detector_id", "status", "publish_frequency", "updated_at", "active_findings"),
        )

        state.record_region_stat(region, "guardduty_enabled", bool(detector_ids))

        if not detector_ids:
            print(f"  [!] GuardDuty NOT ENABLED in {region}")
            state.add(
                SEVERITY_HIGH, region, "GuardDuty",
                "GuardDuty not enabled",
                "No GuardDuty detectors found — threat detection is inactive.",
                "Enable GuardDuty in every region. It analyses CloudTrail, VPC Flow Logs, "
                "and DNS logs for threats with zero configuration overhead. "
                "Consider using AWS Organizations to enable it account-wide.",
            )

    except ClientError as exc:
        print(f"  [guardduty] {region}: {exc}")


def _check_securityhub(region: str, state: MonitoringState) -> None:
    try:
        sh = boto3.client("securityhub", region_name=region)
        sh.describe_hub()
        standards = paginate(sh, "get_enabled_standards", "StandardsSubscriptions")
        std_rows = [
            (
                s.get("StandardsArn", "").split("/")[-1],
                s.get("StandardsSubscriptionArn", ""),
                s.get("StandardsStatus", ""),
            )
            for s in standards
        ]
        print_result(
            f"SecurityHub:Standards @ '{region}'",
            std_rows,
            ("standard", "subscription_arn", "status"),
        )

        state.record_region_stat(region, "securityhub_enabled", True)
        state.record_region_stat(region, "securityhub_standards", len(standards))

        if not standards:
            print(f"  [!] Security Hub enabled but NO standards active in {region}")
            state.add(
                SEVERITY_HIGH, region, "Security Hub",
                "Security Hub enabled but no standards subscribed",
                "Security Hub is running but not evaluating any compliance framework.",
                "Subscribe to at least: AWS Foundational Security Best Practices (FSBP) "
                "and CIS AWS Foundations Benchmark. These provide immediate visibility "
                "into misconfigurations across IAM, S3, EC2, RDS, and more.",
            )
        else:
            ready    = [s for s in standards if s.get("StandardsStatus") == "READY"]
            not_ready = [s for s in standards if s.get("StandardsStatus") != "READY"]
            if not_ready:
                state.add(
                    SEVERITY_LOW, region, "Security Hub",
                    f"{len(not_ready)} standard(s) not in READY state",
                    ", ".join(s.get("StandardsArn", "").split("/")[-1] for s in not_ready),
                    "Check Security Hub for standards that are still initialising or in a FAILED state.",
                )
            else:
                state.ok(region, "Security Hub",
                         f"Enabled with {len(standards)} active standard(s)")

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("InvalidAccessException", "ResourceNotFoundException"):
            print(f"  [!] Security Hub NOT ENABLED in {region}")
            state.add(
                SEVERITY_HIGH, region, "Security Hub",
                "Security Hub not enabled",
                "Centralised security findings aggregation is not active.",
                "Enable Security Hub and subscribe to AWS FSBP and CIS Benchmark standards. "
                "If using AWS Organizations, enable it centrally via the delegated administrator account.",
            )
            state.record_region_stat(region, "securityhub_enabled", False)
        else:
            print(f"  [securityhub] {region}: {exc}")


def _check_eventbridge(region: str, state: MonitoringState) -> None:
    try:
        eb = boto3.client("events", region_name=region)
        buses = eb.list_event_buses().get("EventBuses", [])
        eb_rows = []

        for bus in buses:
            bus_name = bus["Name"]
            rules = paginate(eb, "list_rules", "Rules", EventBusName=bus_name)
            for rule in rules:
                eb_rows.append((
                    bus_name,
                    rule["Name"],
                    rule.get("State", ""),
                    rule.get("ScheduleExpression", "") or rule.get("EventPattern", ""),
                    rule.get("Description", ""),
                ))

        print_result(
            f"EventBridge:Rules @ '{region}'",
            eb_rows,
            ("bus", "rule_name", "state", "schedule_or_pattern", "description"),
        )

        state.record_region_stat(region, "eventbridge_rule_count", len(eb_rows))

        disabled = [r for r in eb_rows if r[2] == "DISABLED"]
        if disabled:
            state.add(
                SEVERITY_LOW, region, "EventBridge",
                f"{len(disabled)} disabled rule(s)",
                ", ".join(r[1] for r in disabled),
                "Review disabled EventBridge rules — they may represent orphaned automation "
                "or rules that were turned off during an incident and never re-enabled.",
            )

        if not eb_rows:
            print(f"  [!] No EventBridge rules in {region}")
            state.add(
                SEVERITY_LOW, region, "EventBridge",
                "No EventBridge rules",
                "No event-driven automation rules are configured in this region.",
                "Consider adding EventBridge rules for: AWS Health events, "
                "Config rule non-compliance notifications, GuardDuty findings, "
                "and EC2 state-change alerts routed to SNS/Slack/PagerDuty.",
            )
        else:
            if not disabled:
                state.ok(region, "EventBridge", f"{len(eb_rows)} active rule(s)")

    except ClientError as exc:
        print(f"  [eventbridge] {region}: {exc}")


# ---------------------------------------------------------------------------
# Monitoring sub-checkers — EKS, RDS, Lambda
# ---------------------------------------------------------------------------

def _check_eks_monitoring(region: str, state: MonitoringState) -> None:
    try:
        eks = boto3.client("eks", region_name=region)
        cw  = boto3.client("cloudwatch", region_name=region)

        cluster_names = paginate(eks, "list_clusters", "clusters")
        if not cluster_names:
            state.ok(region, "EKS Monitoring", "No EKS clusters in region")
            return

        rows = []
        for name in cluster_names:
            try:
                cluster = eks.describe_cluster(name=name)["cluster"]
            except ClientError as exc:
                print(f"  [eks-monitoring] {region} describe {name}: {exc}")
                continue

            logging_cfg  = cluster.get("logging", {}).get("clusterLogging", [])
            enabled_types: list[str] = []
            for entry in logging_cfg:
                if entry.get("enabled"):
                    enabled_types.extend(entry.get("types", []))

            all_log_types  = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
            missing_logs   = all_log_types - set(enabled_types)

            # Container Insights — look for a CloudWatch agent or ADOT add-on
            try:
                addons = paginate(eks, "list_addons", "addons", clusterName=name)
            except ClientError:
                addons = []
            insights_addons = [a for a in addons if "cloudwatch" in a.lower() or "adot" in a.lower() or "amazon-cloudwatch" in a.lower()]
            has_insights = bool(insights_addons)

            # Any CW alarms referencing this cluster
            try:
                alarms_resp = cw.describe_alarms_for_metric(
                    Namespace="ContainerInsights",
                    MetricName="node_cpu_utilization",
                    Dimensions=[{"Name": "ClusterName", "Value": name}],
                )
                has_alarms = bool(alarms_resp.get("MetricAlarms"))
            except ClientError:
                has_alarms = False

            rows.append((
                name,
                ", ".join(sorted(enabled_types)) or "none",
                ", ".join(sorted(missing_logs)) or "—",
                "Yes" if has_insights else "No",
                "Yes" if has_alarms   else "No",
            ))

            if missing_logs:
                state.add(
                    SEVERITY_HIGH, region, "EKS Monitoring",
                    f"Cluster '{name}' missing control plane log types: {', '.join(sorted(missing_logs))}",
                    "Without audit and API logs, Kubernetes API activity cannot be reviewed for security incidents.",
                    f"Enable all log types: aws eks update-cluster-config --name {name} "
                    f"--region {region} --logging '{{\"clusterLogging\":[{{\"types\":[\"api\",\"audit\","
                    f"\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}}]}}'",
                )
            else:
                state.ok(region, "EKS Monitoring", f"Cluster '{name}' — all control plane logs enabled")

            if not has_insights:
                state.add(
                    SEVERITY_MEDIUM, region, "EKS Monitoring",
                    f"Cluster '{name}' — Container Insights not detected",
                    "Node and pod-level metrics (CPU, memory, network, disk) are not being "
                    "collected in CloudWatch.",
                    f"Deploy the CloudWatch agent via the amazon-cloudwatch-observability EKS add-on: "
                    f"aws eks create-addon --cluster-name {name} --addon-name amazon-cloudwatch-observability",
                )
            else:
                state.ok(region, "EKS Monitoring", f"Cluster '{name}' — Container Insights add-on present")

            if not has_alarms:
                state.add(
                    SEVERITY_LOW, region, "EKS Monitoring",
                    f"Cluster '{name}' — no CloudWatch alarms on ContainerInsights metrics",
                    "Node CPU/memory pressure and pod failure conditions will go undetected.",
                    "Create alarms on ContainerInsights metrics: node_cpu_utilization, "
                    "node_memory_utilization, pod_cpu_utilization, and cluster_failed_node_count.",
                )

        print_result(
            f"EKS:Monitoring @ '{region}'",
            rows,
            ("cluster", "enabled_logs", "missing_logs", "container_insights", "cw_alarms"),
        )

    except ClientError as exc:
        print(f"  [eks-monitoring] {region}: {exc}")


def _check_rds_monitoring(region: str, state: MonitoringState) -> None:
    try:
        rds = boto3.client("rds", region_name=region)
        cw  = boto3.client("cloudwatch", region_name=region)

        instances = paginate(rds, "describe_db_instances", "DBInstances")
        if not instances:
            state.ok(region, "RDS Monitoring", "No RDS instances in region")
            return

        # Event subscriptions for this region
        try:
            subs = paginate(rds, "describe_event_subscriptions", "EventSubscriptionsList")
            has_event_subs = bool(subs)
        except ClientError:
            has_event_subs = False
            subs = []

        rows = []
        for db in instances:
            db_id              = db["DBInstanceIdentifier"]
            enhanced_mon       = db.get("MonitoringInterval", 0) > 0
            perf_insights      = db.get("PerformanceInsightsEnabled", False)
            deletion_protection = db.get("DeletionProtection", False)
            multi_az           = db.get("MultiAZ", False)

            # Check for alarms on key RDS metrics
            alarm_metrics = ["CPUUtilization", "FreeStorageSpace", "DatabaseConnections"]
            alarmed_metrics: list[str] = []
            for metric in alarm_metrics:
                try:
                    resp = cw.describe_alarms_for_metric(
                        Namespace="AWS/RDS",
                        MetricName=metric,
                        Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                    )
                    if resp.get("MetricAlarms"):
                        alarmed_metrics.append(metric)
                except ClientError:
                    pass

            missing_alarms = [m for m in alarm_metrics if m not in alarmed_metrics]

            rows.append((
                db_id,
                db.get("DBInstanceClass", ""),
                db.get("Engine", ""),
                "Yes" if enhanced_mon      else "No ⚠️",
                "Yes" if perf_insights     else "No ⚠️",
                ", ".join(alarmed_metrics) or "none",
                ", ".join(missing_alarms)  or "—",
                "Yes" if multi_az          else "No",
                "Yes" if deletion_protection else "No",
            ))

            if not enhanced_mon:
                state.add(
                    SEVERITY_MEDIUM, region, "RDS Monitoring",
                    f"Instance '{db_id}' — Enhanced Monitoring disabled",
                    "OS-level metrics (CPU steal, filesystem I/O, process list) are unavailable.",
                    f"Enable Enhanced Monitoring: aws rds modify-db-instance "
                    f"--db-instance-identifier {db_id} --monitoring-interval 60 "
                    f"--monitoring-role-arn <arn:aws:iam::ACCOUNT:role/rds-monitoring-role>",
                )
            else:
                state.ok(region, "RDS Monitoring", f"Instance '{db_id}' — Enhanced Monitoring enabled")

            if not perf_insights:
                state.add(
                    SEVERITY_MEDIUM, region, "RDS Monitoring",
                    f"Instance '{db_id}' — Performance Insights disabled",
                    "Slow query analysis, wait event breakdown, and top SQL are unavailable.",
                    f"Enable Performance Insights: aws rds modify-db-instance "
                    f"--db-instance-identifier {db_id} --enable-performance-insights",
                )
            else:
                state.ok(region, "RDS Monitoring", f"Instance '{db_id}' — Performance Insights enabled")

            if missing_alarms:
                state.add(
                    SEVERITY_HIGH, region, "RDS Monitoring",
                    f"Instance '{db_id}' — missing alarms: {', '.join(missing_alarms)}",
                    "Critical database health metrics have no alerting.",
                    f"Create CloudWatch alarms on {', '.join(missing_alarms)} for "
                    f"DBInstanceIdentifier={db_id} in namespace AWS/RDS.",
                )
            else:
                state.ok(region, "RDS Monitoring", f"Instance '{db_id}' — key metric alarms present")

        print_result(
            f"RDS:Monitoring @ '{region}'",
            rows,
            ("id", "class", "engine", "enhanced_mon", "perf_insights",
             "alarmed_metrics", "missing_alarms", "multi_az", "deletion_protection"),
        )

        if not has_event_subs:
            state.add(
                SEVERITY_MEDIUM, region, "RDS Monitoring",
                "No RDS event subscriptions configured",
                "Failover, maintenance, low-storage, and parameter group change events "
                "will not generate notifications.",
                "Create an RDS event subscription for source-type 'db-instance' covering "
                "event categories: availability, failover, failure, low storage, maintenance, notification.",
            )
        else:
            state.ok(region, "RDS Monitoring",
                     f"{len(subs)} event subscription(s) configured")

    except ClientError as exc:
        print(f"  [rds-monitoring] {region}: {exc}")


def _check_lambda_monitoring(region: str, state: MonitoringState) -> None:
    try:
        lam  = boto3.client("lambda",     region_name=region)
        cw   = boto3.client("cloudwatch", region_name=region)
        logs = boto3.client("logs",       region_name=region)

        functions = paginate(lam, "list_functions", "Functions")
        if not functions:
            state.ok(region, "Lambda Monitoring", "No Lambda functions in region")
            return

        rows = []
        for fn in functions:
            fn_name   = fn["FunctionName"]
            fn_arn    = fn["FunctionArn"]
            runtime   = fn.get("Runtime", "")

            # X-Ray tracing
            tracing = fn.get("TracingConfig", {}).get("Mode", "PassThrough")
            has_xray = tracing == "Active"

            # DLQ / destination
            dlq_arn = fn.get("DeadLetterConfig", {}).get("TargetArn", "")

            try:
                dest_cfg = lam.get_function_event_invoke_config(FunctionName=fn_name)
                dest_on_failure = (
                    dest_cfg.get("DestinationConfig", {})
                             .get("OnFailure", {})
                             .get("Destination", "")
                )
            except ClientError:
                dest_on_failure = ""

            has_failure_dest = bool(dlq_arn or dest_on_failure)

            # CloudWatch alarms on Errors and Throttles
            alarm_metrics = ["Errors", "Throttles", "Duration"]
            alarmed: list[str] = []
            for metric in alarm_metrics:
                try:
                    resp = cw.describe_alarms_for_metric(
                        Namespace="AWS/Lambda",
                        MetricName=metric,
                        Dimensions=[{"Name": "FunctionName", "Value": fn_name}],
                    )
                    if resp.get("MetricAlarms"):
                        alarmed.append(metric)
                except ClientError:
                    pass

            missing_alarms = [m for m in alarm_metrics if m not in alarmed]

            # Log group retention
            log_group_name = f"/aws/lambda/{fn_name}"
            try:
                lg_resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
                lg_list = [g for g in lg_resp.get("logGroups", []) if g["logGroupName"] == log_group_name]
                log_group_exists   = bool(lg_list)
                log_retention_days = lg_list[0].get("retentionInDays", None) if lg_list else None
            except ClientError:
                log_group_exists   = False
                log_retention_days = None

            rows.append((
                fn_name,
                runtime,
                "Active" if has_xray        else "PassThrough",
                "Yes"    if has_failure_dest else "No ⚠️",
                ", ".join(alarmed)           or "none",
                ", ".join(missing_alarms)    or "—",
                str(log_retention_days)      if log_retention_days else ("no retention" if log_group_exists else "no log group"),
            ))

            if not has_xray:
                state.add(
                    SEVERITY_LOW, region, "Lambda Monitoring",
                    f"Function '{fn_name}' — X-Ray tracing not active",
                    f"Tracing mode is '{tracing}'. Distributed tracing and latency "
                    "breakdown across downstream calls are unavailable.",
                    f"Enable active tracing: aws lambda update-function-configuration "
                    f"--function-name {fn_name} --tracing-config Mode=Active",
                )
            else:
                state.ok(region, "Lambda Monitoring", f"Function '{fn_name}' — X-Ray active")

            if not has_failure_dest:
                state.add(
                    SEVERITY_MEDIUM, region, "Lambda Monitoring",
                    f"Function '{fn_name}' — no DLQ or on-failure destination",
                    "Async invocation failures will be silently dropped after retries are exhausted.",
                    f"Configure a Dead Letter Queue (SQS) or on-failure EventBridge/SNS destination: "
                    f"aws lambda put-function-event-invoke-config --function-name {fn_name} "
                    f"--destination-config '{{\"OnFailure\":{{\"Destination\":\"<arn>\"}}}}'",
                )
            else:
                state.ok(region, "Lambda Monitoring", f"Function '{fn_name}' — failure destination configured")

            if missing_alarms:
                state.add(
                    SEVERITY_HIGH, region, "Lambda Monitoring",
                    f"Function '{fn_name}' — missing alarms: {', '.join(missing_alarms)}",
                    "Error spikes, throttling, and timeout conditions will go undetected.",
                    f"Create CloudWatch alarms on {', '.join(missing_alarms)} for "
                    f"FunctionName={fn_name} in namespace AWS/Lambda.",
                )
            else:
                state.ok(region, "Lambda Monitoring", f"Function '{fn_name}' — key metric alarms present")

            if log_group_exists and log_retention_days is None:
                state.add(
                    SEVERITY_LOW, region, "Lambda Monitoring",
                    f"Function '{fn_name}' — log group has no retention policy",
                    f"Log group {log_group_name} will retain logs indefinitely, "
                    "incurring unbounded storage costs.",
                    f"Set a retention policy: aws logs put-retention-policy "
                    f"--log-group-name {log_group_name} --retention-in-days 90",
                )
            elif not log_group_exists:
                state.add(
                    SEVERITY_MEDIUM, region, "Lambda Monitoring",
                    f"Function '{fn_name}' — no log group found",
                    f"Log group {log_group_name} does not exist. The function may never "
                    "have been invoked, or logging permissions may be missing.",
                    "Ensure the Lambda execution role has logs:CreateLogGroup, "
                    "logs:CreateLogStream, and logs:PutLogEvents permissions.",
                )

        print_result(
            f"Lambda:Monitoring @ '{region}'",
            rows,
            ("function", "runtime", "xray", "failure_dest",
             "alarmed_metrics", "missing_alarms", "log_retention"),
        )

    except ClientError as exc:
        print(f"  [lambda-monitoring] {region}: {exc}")


# ---------------------------------------------------------------------------
# Post-scan report generator
# ---------------------------------------------------------------------------

def _generate_report(state: MonitoringState, selected_keys: list[str]) -> None:
    findings = state.findings
    if not findings:
        print("\n\nNo findings collected — nothing to report.\n")
        return

    non_ok = [f for f in findings if f.severity != SEVERITY_OK]
    ok     = [f for f in findings if f.severity == SEVERITY_OK]

    # Count by severity
    counts: dict[str, int] = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH:     0,
        SEVERITY_MEDIUM:   0,
        SEVERITY_LOW:      0,
        SEVERITY_OK:       len(ok),
    }
    for f in non_ok:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Overall score: 100 minus weighted penalty
    penalty = (
        counts[SEVERITY_CRITICAL] * 25 +
        counts[SEVERITY_HIGH]     * 10 +
        counts[SEVERITY_MEDIUM]   *  4 +
        counts[SEVERITY_LOW]      *  1
    )
    score = max(0, 100 - penalty)

    if score >= 80:
        grade, grade_label = "A", "Good"
    elif score >= 60:
        grade, grade_label = "B", "Moderate"
    elif score >= 40:
        grade, grade_label = "C", "Poor"
    else:
        grade, grade_label = "D", "Critical"

    sep = "\n" + ("=" * 70)

    print(sep)
    if _MD_MODE:
        print("\n## Monitoring Coverage Report\n")
    else:
        print("\n  MONITORING COVERAGE REPORT\n")

    # Score card
    score_rows = [
        ("Overall Score",    f"{score}/100  (Grade {grade} — {grade_label})"),
        ("Checks Run",       ", ".join(selected_keys)),
        ("Regions Scanned",  str(len(REGIONS))),
        (f"{_SEVERITY_ICON[SEVERITY_CRITICAL]} Critical", str(counts[SEVERITY_CRITICAL])),
        (f"{_SEVERITY_ICON[SEVERITY_HIGH]}     High",     str(counts[SEVERITY_HIGH])),
        (f"{_SEVERITY_ICON[SEVERITY_MEDIUM]}   Medium",   str(counts[SEVERITY_MEDIUM])),
        (f"{_SEVERITY_ICON[SEVERITY_LOW]}      Low",      str(counts[SEVERITY_LOW])),
        (f"{_SEVERITY_ICON[SEVERITY_OK]}       Passed",   str(counts[SEVERITY_OK])),
    ]
    fmt = "github" if _MD_MODE else "simple"
    print(tabulate(score_rows, tablefmt=fmt))

    # Findings grouped by severity
    for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW):
        group = [f for f in non_ok if f.severity == sev]
        if not group:
            continue

        icon = _SEVERITY_ICON[sev]
        if _MD_MODE:
            print(f"\n### {icon} {sev} ({len(group)} finding{'s' if len(group) != 1 else ''})\n")
        else:
            print(f"\n  {icon}  {sev}  ({len(group)} finding{'s' if len(group) != 1 else ''})")
            print("  " + "-" * 60)

        for f in sorted(group, key=lambda x: (x.region, x.service)):
            if _MD_MODE:
                print(f"#### [{f.service}] {f.title} — `{f.region}`\n")
                print(f"> {f.detail}\n")
                print(f"**Recommendation:** {f.recommendation}\n")
            else:
                print(f"\n  [{f.service}] {f.title}")
                print(f"  Region : {f.region}")
                print(f"  Detail : {f.detail}")
                print(f"  Fix    : {f.recommendation}")

    # Passed checks summary
    if ok:
        if _MD_MODE:
            print(f"\n### {_SEVERITY_ICON[SEVERITY_OK]} Passed ({len(ok)})\n")
            ok_rows = [(f.region, f.service, f.title) for f in ok]
            print(tabulate(ok_rows, ("region", "service", "detail"), tablefmt="github"))
        else:
            print(f"\n  {_SEVERITY_ICON[SEVERITY_OK]}  PASSED ({len(ok)})")
            print("  " + "-" * 60)
            ok_rows = [(f.region, f.service, f.title) for f in ok]
            print(tabulate(ok_rows, ("region", "service", "detail"), tablefmt="simple"))

    # Per-region summary table
    if _MD_MODE:
        print("\n### Per-Region Summary\n")
    else:
        print("\n  PER-REGION SUMMARY")
        print("  " + "-" * 60)

    region_rows = []
    for region in REGIONS:
        region_findings = [f for f in non_ok if f.region == region]
        crit = sum(1 for f in region_findings if f.severity == SEVERITY_CRITICAL)
        high = sum(1 for f in region_findings if f.severity == SEVERITY_HIGH)
        med  = sum(1 for f in region_findings if f.severity == SEVERITY_MEDIUM)
        low  = sum(1 for f in region_findings if f.severity == SEVERITY_LOW)
        passed = sum(1 for f in findings if f.region == region and f.severity == SEVERITY_OK)
        region_rows.append((
            region,
            f"🔴 {crit}" if crit else "-",
            f"🟠 {high}" if high else "-",
            f"🟡 {med}"  if med  else "-",
            f"🔵 {low}"  if low  else "-",
            f"🟢 {passed}",
        ))

    print(tabulate(
        region_rows,
        ("region", "critical", "high", "medium", "low", "passed"),
        tablefmt="github" if _MD_MODE else "simple",
    ))

    print(sep + "\n")


# Map of short names → (display label, checker function)
MONITORING_CHECKS: dict[str, tuple[str, Callable]] = {
    "cloudwatch":      ("CloudWatch Alarms & Dashboards",    _check_cloudwatch),
    "cloudwatch-logs": ("CloudWatch Logs & Metric Filters",  _check_cloudwatch_logs),
    "cloudtrail":      ("CloudTrail",                        _check_cloudtrail),
    "config":          ("AWS Config Recorders & Rules",      _check_config),
    "guardduty":       ("GuardDuty",                         _check_guardduty),
    "securityhub":     ("Security Hub",                      _check_securityhub),
    "eventbridge":     ("EventBridge Rules",                 _check_eventbridge),
    "eks":             ("EKS Cluster Monitoring",            _check_eks_monitoring),
    "rds":             ("RDS Enhanced Monitoring & Alarms",  _check_rds_monitoring),
    "lambda":          ("Lambda Errors, Tracing & DLQs",     _check_lambda_monitoring),
}


def _monitoring_menu() -> list[str]:
    """
    Interactive numbered menu.  Returns the list of selected check keys.
    Accepts comma-separated numbers, ranges (1-3), or 'all'.
    """
    items = list(MONITORING_CHECKS.items())
    print("\n=== MONITORING AUDIT — Select checks to run ===\n")
    for idx, (key, (label, _)) in enumerate(items, start=1):
        print(f"  {idx:2}.  {label}  [{key}]")
    print(f"\n  Enter numbers/ranges (e.g. 1,3,5-7), names, or 'all'")
    print("  Press Enter with no input to run ALL checks.\n")

    try:
        raw = input("  Your selection: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if not raw or raw.lower() == "all":
        return [k for k, _ in items]

    selected: list[str] = []
    key_names = [k for k, _ in items]
    for token in raw.replace(" ", "").split(","):
        if "-" in token and token.replace("-", "").isdigit():
            start_s, end_s = token.split("-", 1)
            for n in range(int(start_s), int(end_s) + 1):
                if 1 <= n <= len(items):
                    selected.append(key_names[n - 1])
        elif token.isdigit():
            n = int(token)
            if 1 <= n <= len(items):
                selected.append(key_names[n - 1])
        elif token in MONITORING_CHECKS:
            selected.append(token)
        else:
            print(f"  [!] Ignoring unknown selection: {token!r}")

    # deduplicate while preserving order
    seen: set[str] = set()
    deduped = []
    for k in selected:
        if k not in seen:
            seen.add(k)
            deduped.append(k)
    return deduped


# ---------------------------------------------------------------------------
# Monitoring entry point
# ---------------------------------------------------------------------------
def list_monitoring(input_args: list[str]) -> None:
    """
    Audit every region for monitoring coverage.

    Usage:
      aws_guru.py monitoring                         # interactive menu
      aws_guru.py monitoring all                     # run every check
      aws_guru.py monitoring cloudwatch cloudtrail   # named checks
      aws_guru.py monitoring 1 3 5                   # checks by number
    """
    # Determine which checks to run
    if not input_args:
        selected_keys = _monitoring_menu()
    else:
        # Allow 'all' shorthand on the command line
        if input_args == ["all"]:
            selected_keys = list(MONITORING_CHECKS.keys())
        else:
            # Accept numbers or names from the command line too
            items = list(MONITORING_CHECKS.keys())
            selected_keys = []
            for token in input_args:
                if token.isdigit():
                    n = int(token)
                    if 1 <= n <= len(items):
                        selected_keys.append(items[n - 1])
                    else:
                        print(f"  [!] No check numbered {n}")
                elif token in MONITORING_CHECKS:
                    selected_keys.append(token)
                else:
                    print(f"  [!] Unknown check name: {token!r}")

    if not selected_keys:
        print("No checks selected — nothing to do.")
        return

    labels = [MONITORING_CHECKS[k][0] for k in selected_keys]
    print(f"\n\nRunning: {', '.join(labels)}\n")

    state = MonitoringState()

    for region in REGIONS:
        print(f"\n--- Region: {region} ---")
        for key in selected_keys:
            _, checker = MONITORING_CHECKS[key]
            checker(region, state)

    _generate_report(state, selected_keys)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
COMMANDS: dict[str, tuple[Callable, list[str]]] = {
    "ec2":         (list_ec2,         []),
    "eks":         (list_eks,         []),
    "elb":         (list_elb,         []),
    "elbv2":       (list_elbv2,       []),
    "rds":         (list_rds,         []),
    "elasticache": (list_elasticache, []),
    "vpc":         (list_vpc,         []),
    "sg":          (list_sg,          []),
    "volume":      (list_volume,      []),
    "dbss":        (list_dbss,        []),
    "ec2ss":       (list_ec2ss,       []),
    "ecss":        (list_ecss,        []),
    "s3":          (list_s3,          []),
    "monitoring":  (list_monitoring,  []),
}


class _Tee(io.TextIOBase):
    """Write to both a real stream and an in-memory buffer simultaneously."""

    def __init__(self, real: io.TextIOBase, buf: io.StringIO) -> None:
        self._real = real
        self._buf = buf

    def write(self, s: str) -> int:
        self._real.write(s)
        self._buf.write(s)
        return len(s)

    def flush(self) -> None:
        self._real.flush()
        self._buf.flush()


def usage() -> None:
    cmds = ", ".join(sorted(COMMANDS))
    print(
        f"Usage: aws_guru.py [--md] [command] [options]\n"
        f"  --md        Emit Markdown output and save to a timestamped .md file\n"
        f"Commands: {cmds}"
    )


def main() -> None:
    global _MD_MODE

    args = sys.argv[1:]

    # Pull --md out of the argument list wherever it appears
    md_flag = "--md" in args
    args = [a for a in args if a != "--md"]

    if md_flag:
        _MD_MODE = True

    # ── Dispatch ────────────────────────────────────────────────────────────
    def _run(args: list[str]) -> None:
        if not args:
            list_vpc([])
            list_ec2([])
            list_elb([])
            list_elbv2([])
            return

        cmd = args[0]
        if cmd in ("-h", "--help"):
            usage()
            return

        if cmd not in COMMANDS:
            print(f"Unknown command: {cmd!r}")
            usage()
            sys.exit(1)

        func, _ = COMMANDS[cmd]
        func(args[1:])

    # ── Markdown output mode ────────────────────────────────────────────────
    if _MD_MODE:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        cmd_slug = args[0] if args else "report"
        filename = f"aws_guru_{cmd_slug}_{timestamp}.md"

        buf = io.StringIO()
        tee = _Tee(sys.stdout, buf)  # type: ignore[arg-type]

        # Write Markdown front-matter
        buf.write(f"# aws_guru report — {cmd_slug}\n\n")
        buf.write(f"_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_\n\n")

        old_stdout = sys.stdout
        sys.stdout = tee  # type: ignore[assignment]
        try:
            _run(args)
            print("\n\n--- FINISHED\n\n")
        finally:
            sys.stdout = old_stdout

        md_content = buf.getvalue()
        out_path = os.path.join(os.getcwd(), filename)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(md_content)
        print(f"\n[md] Report saved to: {out_path}")
    else:
        _run(args)
        print("\n\n--- FINISHED\n\n")


if __name__ == "__main__":
    main()
