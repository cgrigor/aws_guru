#!/usr/bin/env python3
# Copyright 2026 Chris
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
# ---------------------------------------------------------------------------

def _check_cloudwatch(region: str) -> None:
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
        if not all_alarm_rows:
            print(f"  [!] NO CloudWatch alarms found in {region}")

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
    except ClientError as exc:
        print(f"  [cloudwatch] {region}: {exc}")


def _check_cloudwatch_logs(region: str) -> None:
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
        if not lg_rows:
            print(f"  [!] No CloudWatch Log Groups in {region}")

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
    except ClientError as exc:
        print(f"  [cloudwatch-logs] {region}: {exc}")


def _check_cloudtrail(region: str) -> None:
    try:
        ct = boto3.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        trail_rows = []
        for trail in trails:
            status_resp = ct.get_trail_status(Name=trail["TrailARN"])
            trail_rows.append((
                trail["Name"],
                trail["TrailARN"],
                "Yes" if trail.get("IsMultiRegionTrail") else "No",
                "Yes" if status_resp.get("IsLogging") else "NO ⚠️",
                trail.get("S3BucketName", ""),
                "Yes" if trail.get("CloudWatchLogsLogGroupArn") else "No",
            ))
        print_result(
            f"CloudTrail:Trails @ '{region}'",
            trail_rows,
            ("name", "arn", "multi_region", "is_logging", "s3_bucket", "cw_logs"),
        )
        if not trail_rows:
            print(f"  [!] NO CloudTrail trails found in {region}")
    except ClientError as exc:
        print(f"  [cloudtrail] {region}: {exc}")


def _check_config(region: str) -> None:
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
        if not rec_rows:
            print(f"  [!] No AWS Config recorders in {region}")

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
        if not rule_rows:
            print(f"  [!] No AWS Config rules in {region}")
    except ClientError as exc:
        print(f"  [config] {region}: {exc}")


def _check_guardduty(region: str) -> None:
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
            gd_rows.append((
                det_id,
                det.get("Status", ""),
                det.get("FindingPublishingFrequency", ""),
                det.get("UpdatedAt", ""),
                str(sum(finding_count.values())) if finding_count else "0",
            ))
        print_result(
            f"GuardDuty:Detectors @ '{region}'",
            gd_rows,
            ("detector_id", "status", "publish_frequency", "updated_at", "active_findings"),
        )
        if not gd_rows:
            print(f"  [!] GuardDuty NOT ENABLED in {region}")
    except ClientError as exc:
        print(f"  [guardduty] {region}: {exc}")


def _check_securityhub(region: str) -> None:
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
        if not std_rows:
            print(f"  [!] Security Hub enabled but NO standards active in {region}")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("InvalidAccessException", "ResourceNotFoundException"):
            print(f"  [!] Security Hub NOT ENABLED in {region}")
        else:
            print(f"  [securityhub] {region}: {exc}")


def _check_eventbridge(region: str) -> None:
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
        if not eb_rows:
            print(f"  [!] No EventBridge rules in {region}")
    except ClientError as exc:
        print(f"  [eventbridge] {region}: {exc}")


# Map of short names → (display label, checker function)
MONITORING_CHECKS: dict[str, tuple[str, Callable]] = {
    "cloudwatch":      ("CloudWatch Alarms & Dashboards", _check_cloudwatch),
    "cloudwatch-logs": ("CloudWatch Logs & Metric Filters", _check_cloudwatch_logs),
    "cloudtrail":      ("CloudTrail",                     _check_cloudtrail),
    "config":          ("AWS Config Recorders & Rules",   _check_config),
    "guardduty":       ("GuardDuty",                      _check_guardduty),
    "securityhub":     ("Security Hub",                   _check_securityhub),
    "eventbridge":     ("EventBridge Rules",              _check_eventbridge),
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

    for region in REGIONS:
        print(f"\n--- Region: {region} ---")
        for key in selected_keys:
            _, checker = MONITORING_CHECKS[key]
            checker(region)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
COMMANDS: dict[str, tuple[Callable, list[str]]] = {
    "ec2":         (list_ec2,         []),
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
