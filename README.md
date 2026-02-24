# aws_guru

A CLI tool for auditing AWS infrastructure across multiple regions. Inventories common resource types and performs a comprehensive monitoring coverage audit with scored findings and actionable recommendations.

## Features

- Scans **9 AWS regions** simultaneously across all resource types
- **Inventory commands** for EC2, EKS, ELB/ALB, RDS, ElastiCache, VPC, S3, Security Groups, EBS Volumes, and snapshots
- **EKS deep scan** — clusters, node groups (with scaling config), and Fargate profiles per region
- **Monitoring audit** across CloudWatch, CloudTrail, AWS Config, GuardDuty, Security Hub, and EventBridge
- **Interactive selector** — choose which monitoring checks to run via a numbered menu
- **Scored report** — overall grade, findings grouped by severity (Critical → Low), per-region summary table, and concrete fix recommendations for every issue
- **Markdown output** — `--md` flag saves a full timestamped report to a `.md` file

## Requirements

- Python 3.10+
- AWS credentials configured (via `~/.aws/credentials`, environment variables, or IAM role)

```bash
pip install -r requirements.txt
```

`requirements.txt`:

```
boto3>=1.37.0
botocore>=1.37.0
tabulate>=0.9.0
```

## Usage

```
python3 aws_guru.py [--md] [command] [options]
```

The `--md` flag can be placed anywhere in the command and works with every subcommand.

---

### Inventory Commands

| Command | Description |
|---|---|
| `ec2` | EC2 instances across all regions |
| `eks` | EKS clusters, node groups, and Fargate profiles |
| `elb` | Classic load balancers |
| `elbv2` | Application / Network load balancers |
| `rds` | RDS database instances |
| `elasticache` | ElastiCache clusters |
| `vpc` | VPCs |
| `sg` | Security groups |
| `volume` | EBS volumes |
| `dbss` | RDS snapshots |
| `ec2ss` | EC2 snapshots (owned by this account) |
| `ecss` | ElastiCache snapshots |
| `s3` | S3 buckets (global) |

---

### EKS Clusters

```bash
python3 aws_guru.py eks
python3 aws_guru.py --md eks
```

Produces three tables per region:

| Table | Columns |
|---|---|
| **EKS:Clusters** | Name, Kubernetes version, status, API endpoint, `Environment` tag, creation time |
| **EKS:NodeGroups** | Cluster, node group name, status, instance type(s), min / desired / max scaling, node version |
| **EKS:FargateProfiles** | Cluster, profile name, status, namespace selectors with label filters |

Clusters with a status other than `ACTIVE` (e.g. `CREATING`, `DEGRADED`, `FAILED`) will be visible in the status column for quick triage.

---

**Examples:**

```bash
# Default run — VPCs, EC2, ELB, ALB
python3 aws_guru.py

# Single resource type
python3 aws_guru.py ec2
python3 aws_guru.py rds

# Save output as Markdown
python3 aws_guru.py --md ec2

# Filter by tag value
python3 aws_guru.py ec2 environment=production

# Sort by column
python3 aws_guru.py ec2 name
```

---

### Monitoring Audit

```bash
python3 aws_guru.py monitoring
```

Running with no further arguments launches an interactive menu:

```
=== MONITORING AUDIT — Select checks to run ===

   1.  CloudWatch Alarms & Dashboards   [cloudwatch]
   2.  CloudWatch Logs & Metric Filters [cloudwatch-logs]
   3.  CloudTrail                       [cloudtrail]
   4.  AWS Config Recorders & Rules     [config]
   5.  GuardDuty                        [guardduty]
   6.  Security Hub                     [securityhub]
   7.  EventBridge Rules                [eventbridge]
   8.  EKS Cluster Monitoring           [eks]
   9.  RDS Enhanced Monitoring & Alarms [rds]
  10.  Lambda Errors, Tracing & DLQs   [lambda]

  Enter numbers/ranges (e.g. 1,3,5-7), names, or 'all'
  Press Enter with no input to run ALL checks.
```

**Selection formats:**

| Input | Result |
|---|---|
| *(blank Enter)* | Run all checks |
| `all` | Run all checks |
| `1,3,5` | Checks 1, 3, and 5 |
| `1-4` | Checks 1 through 4 |
| `1,3,5-7` | Mix of individual and range |
| `cloudwatch,guardduty` | Select by short name |

**You can also skip the menu entirely:**

```bash
# Run everything
python3 aws_guru.py monitoring all

# Select by name
python3 aws_guru.py monitoring cloudwatch cloudtrail guardduty

# Select by number
python3 aws_guru.py monitoring 1 3 5

# Full audit saved to Markdown
python3 aws_guru.py --md monitoring all
```

---

### Monitoring Report

After each monitoring run a scored report is printed automatically.

```
======================================================================

  MONITORING COVERAGE REPORT

Overall Score    85/100  (Grade A — Good)
Checks Run       cloudwatch, cloudtrail, guardduty
Regions Scanned  9
🔴 Critical      0
🟠 High          1
🟡 Medium        2
🔵 Low           1
🟢 Passed        14
```

**Severity weights:**

| Severity | Penalty |
|---|---|
| 🔴 Critical | −25 per finding |
| 🟠 High | −10 per finding |
| 🟡 Medium | −4 per finding |
| 🔵 Low | −1 per finding |

**Grades:** A ≥ 80 · B ≥ 60 · C ≥ 40 · D < 40

Each finding includes:
- The region and service it was detected in
- A plain-English description of the problem
- A **concrete recommendation** (including CLI commands where applicable)

A **per-region summary table** is printed at the end showing the finding breakdown for every region at a glance.

---

### What the Monitoring Audit Checks

#### CloudWatch
- Alarms configured (warns if none exist)
- Alarms currently in `ALARM` state
- Alarms missing descriptions
- Dashboards present

#### CloudWatch Logs
- Log groups present
- Log groups missing retention policies (unbounded cost/compliance risk)
- Metric filters defined for log-based alerting

#### CloudTrail
- Trail exists in region
- Logging is active (`IsLogging`)
- Multi-region trail enabled
- CloudWatch Logs integration (required for real-time API alerting)

#### AWS Config
- Recorder exists and is actively recording
- Config rules defined

#### GuardDuty
- Detector enabled
- Finding publish frequency (warns if set to 6 hours)
- Active unarchived findings, broken down by severity

#### Security Hub
- Hub enabled
- At least one standard subscribed (AWS FSBP, CIS Benchmark, etc.)
- All subscribed standards in `READY` state

#### EventBridge
- Rules present on all event buses
- Disabled rules flagged for review

#### EKS Monitoring
- Control plane logging enabled (API, audit, authenticator, scheduler, controllerManager)
- Container Insights add-on detected (`amazon-cloudwatch-observability` or ADOT)
- CloudWatch alarms exist on ContainerInsights metrics (node CPU/memory, pod failures)

#### RDS Monitoring
- Enhanced Monitoring enabled (OS-level metrics at 60s granularity)
- Performance Insights enabled (slow query analysis, wait events, top SQL)
- CloudWatch alarms on `CPUUtilization`, `FreeStorageSpace`, `DatabaseConnections`
- RDS event subscriptions configured (failover, failure, low storage, maintenance)

#### Lambda Monitoring
- CloudWatch alarms on `Errors`, `Throttles`, `Duration` per function
- Dead Letter Queue (DLQ) or on-failure destination configured for async invocations
- X-Ray active tracing enabled
- Log group exists and has a retention policy set

---

### Markdown Output

Add `--md` to any command to emit Markdown-formatted output and save it to a timestamped file in the current directory:

```bash
python3 aws_guru.py --md monitoring all
# Saves: aws_guru_monitoring_20260224_143000.md
```

The file includes a front-matter header with the command and UTC timestamp, all tables in GitHub-flavoured Markdown, and the full findings report.

---

### Configuring Regions

Edit the `REGIONS` list near the top of `aws_guru.py`:

```python
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
```

---

### Required IAM Permissions

The tool requires read-only access. A minimal IAM policy needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
        "eks:ListFargateProfiles",
        "eks:DescribeFargateProfile",
        "elasticloadbalancing:Describe*",
        "rds:Describe*",
        "elasticache:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListDashboards",
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeConfigRules",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:GetFindingsStatistics",
        "securityhub:DescribeHub",
        "securityhub:GetEnabledStandards",
        "events:ListEventBuses",
        "events:ListRules",
        "eks:ListAddons",
        "eks:DescribeAddon",
        "rds:DescribeEventSubscriptions",
        "lambda:ListFunctions",
        "lambda:GetFunctionEventInvokeConfig",
        "xray:GetSamplingRules"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).
