"""
guardduty-automated-response / lambda / isolate_instance.py

Triggered by EventBridge when GuardDuty raises:
  - UnauthorizedAccess:EC2/SSHBruteForce
  - UnauthorizedAccess:EC2/MaliciousIPCaller
  - CryptoCurrency:EC2/BitcoinTool

What it does:
  1. Parses the GuardDuty finding from the EventBridge event
  2. Extracts the affected EC2 instance ID
  3. Snapshots the current security groups (for audit trail)
  4. Swaps all security groups to the quarantine SG (zero rules)
  5. Tags the instance: Status=QUARANTINED, FindingType, Timestamp
  6. Publishes an enriched alert to SNS
  7. Logs everything to CloudWatch in JSON format
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# ── Logging setup ─────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# ── AWS clients ───────────────────────────────────────────────────────────────
ec2 = boto3.client("ec2")
sns = boto3.client("sns")

# ── Environment variables set by Terraform ────────────────────────────────────
QUARANTINE_SG_ID = os.environ["QUARANTINE_SG_ID"]
SNS_TOPIC_ARN    = os.environ["SNS_TOPIC_ARN"]


# ── Main handler ──────────────────────────────────────────────────────────────
def lambda_handler(event: dict, context) -> dict:
    """
    Entry point. Receives a GuardDuty finding wrapped in an EventBridge event.
    """
    logger.info({"message": "HANDLER_START", "event": event})

    try:
        finding   = parse_finding(event)
        instance  = get_instance_details(finding["instance_id"])
        old_sgs   = isolate_instance(finding["instance_id"], instance)
        tag_instance(finding, old_sgs)
        send_alert(finding, instance, old_sgs)

        logger.info({
            "message":     "ISOLATION_COMPLETE",
            "instance_id": finding["instance_id"],
            "finding_type": finding["type"],
            "severity":    finding["severity"],
        })

        return {
            "statusCode": 200,
            "instanceId": finding["instance_id"],
            "findingType": finding["type"],
            "action": "QUARANTINED",
        }

    except InstanceNotFoundError as exc:
        logger.error({"level": "ERROR", "message": str(exc)})
        raise

    except ClientError as exc:
        logger.error({"level": "ERROR", "message": "AWS API error", "detail": str(exc)})
        raise

    except Exception as exc:
        logger.error({"level": "ERROR", "message": "Unexpected error", "detail": str(exc)})
        raise


# ── Step 1: Parse the GuardDuty finding ──────────────────────────────────────
def parse_finding(event: dict) -> dict:
    """
    Extracts the fields we need from the GuardDuty finding JSON.
    GuardDuty findings arrive inside event['detail'].
    """
    detail      = event.get("detail", {})
    finding_id  = detail.get("id", "unknown")
    finding_type = detail.get("type", "unknown")
    severity    = detail.get("severity", 0)
    region      = detail.get("region", "unknown")
    account_id  = detail.get("accountId", "unknown")
    description = detail.get("description", "No description provided")
    updated_at  = detail.get("updatedAt", datetime.now(timezone.utc).isoformat())

    # Instance ID is nested inside resource.instanceDetails
    resource        = detail.get("resource", {})
    instance_details = resource.get("instanceDetails", {})
    instance_id     = instance_details.get("instanceId")

    if not instance_id:
        raise InstanceNotFoundError(
            f"No EC2 instance ID found in finding {finding_id}. "
            f"Resource type may not be EC2: {resource.get('resourceType')}"
        )

    logger.info({
        "message":      "FINDING_PARSED",
        "finding_id":   finding_id,
        "finding_type": finding_type,
        "severity":     severity,
        "instance_id":  instance_id,
        "region":       region,
    })

    return {
        "id":          finding_id,
        "type":        finding_type,
        "severity":    severity,
        "region":      region,
        "account_id":  account_id,
        "description": description,
        "updated_at":  updated_at,
        "instance_id": instance_id,
        "instance_details": instance_details,
    }


# ── Step 2: Get current instance details ─────────────────────────────────────
def get_instance_details(instance_id: str) -> dict:
    """
    Fetches the current state of the EC2 instance — including its
    existing security groups so we can log them before swapping.
    """
    response = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = response.get("Reservations", [])

    if not reservations:
        raise InstanceNotFoundError(f"Instance {instance_id} not found in EC2")

    instance = reservations[0]["Instances"][0]

    logger.info({
        "message":      "INSTANCE_DETAILS_FETCHED",
        "instance_id":  instance_id,
        "state":        instance["State"]["Name"],
        "current_sgs":  [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
    })

    return instance


# ── Step 3: Swap security groups to quarantine ────────────────────────────────
def isolate_instance(instance_id: str, instance: dict) -> list[str]:
    """
    Records existing security groups then replaces them all
    with the zero-rule quarantine SG. Returns the old SG IDs.
    """
    old_sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

    if QUARANTINE_SG_ID in old_sg_ids and len(old_sg_ids) == 1:
        logger.warning({
            "message":     "ALREADY_QUARANTINED",
            "instance_id": instance_id,
        })
        return old_sg_ids

    logger.info({
        "message":       "SWAPPING_SECURITY_GROUPS",
        "instance_id":   instance_id,
        "removing_sgs":  old_sg_ids,
        "applying_sg":   QUARANTINE_SG_ID,
    })

    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID],
    )

    logger.info({
        "message":     "SECURITY_GROUPS_SWAPPED",
        "instance_id": instance_id,
        "quarantine_sg": QUARANTINE_SG_ID,
    })

    return old_sg_ids


# ── Step 4: Tag the instance ──────────────────────────────────────────────────
def tag_instance(finding: dict, old_sgs: list[str]) -> None:
    """
    Tags the isolated instance so it's identifiable in the console
    and auditable from CloudTrail.
    """
    tags = [
        {"Key": "Status",           "Value": "QUARANTINED"},
        {"Key": "QuarantineTime",   "Value": datetime.now(timezone.utc).isoformat()},
        {"Key": "FindingType",      "Value": finding["type"]},
        {"Key": "FindingId",        "Value": finding["id"]},
        {"Key": "FindingSeverity",  "Value": str(finding["severity"])},
        {"Key": "OriginalSGIds",    "Value": ",".join(old_sgs)},
    ]

    ec2.create_tags(
        Resources=[finding["instance_id"]],
        Tags=tags,
    )

    logger.info({
        "message":     "INSTANCE_TAGGED",
        "instance_id": finding["instance_id"],
        "tags":        {t["Key"]: t["Value"] for t in tags},
    })


# ── Step 5: Send SNS alert ────────────────────────────────────────────────────
def send_alert(finding: dict, instance: dict, old_sgs: list[str]) -> None:
    """
    Publishes an enriched incident notification to SNS.
    Email subscribers get a clear, human-readable alert.
    """
    severity_label = _severity_label(finding["severity"])
    instance_name  = _get_tag(instance, "Name", "unnamed")

    subject = f"[{severity_label}] GuardDuty — EC2 Instance Quarantined | {finding['type']}"

    message = f"""
GUARDDUTY AUTOMATED RESPONSE — EC2 INSTANCE QUARANTINED
═══════════════════════════════════════════════════════

FINDING DETAILS
  Type       : {finding['type']}
  Severity   : {finding['severity']} ({severity_label})
  Finding ID : {finding['id']}
  Detected   : {finding['updated_at']}
  Description: {finding['description']}

AFFECTED INSTANCE
  Instance ID   : {finding['instance_id']}
  Instance Name : {instance_name}
  State         : {instance['State']['Name']}
  Region        : {finding['region']}
  Account       : {finding['account_id']}

ACTION TAKEN
  Status           : QUARANTINED
  Quarantine Time  : {datetime.now(timezone.utc).isoformat()}
  Quarantine SG    : {QUARANTINE_SG_ID} (zero inbound/outbound rules)
  Previous SGs     : {', '.join(old_sgs) if old_sgs else 'none'}

NEXT STEPS
  1. Investigate the instance via AWS Systems Manager Session Manager
     (direct SSH is now blocked by the quarantine SG)
  2. Review GuardDuty finding details in the console
  3. Check CloudTrail for API calls from this instance in the last 24h
  4. If confirmed malicious: capture memory, preserve disk, terminate
  5. If false positive: restore original SGs and remove QUARANTINED tag

AWS CONSOLE LINKS
  GuardDuty Finding : https://{finding['region']}.console.aws.amazon.com/guardduty/home?region={finding['region']}#/findings
  EC2 Instance      : https://{finding['region']}.console.aws.amazon.com/ec2/v2/home?region={finding['region']}#Instances:instanceId={finding['instance_id']}

═══════════════════════════════════════════════════════
This alert was generated automatically by the GuardDuty
Automated Response Lambda — no human action was required
to isolate this instance.
    """.strip()

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=message,
    )

    logger.info({
        "message":     "SNS_ALERT_SENT",
        "instance_id": finding["instance_id"],
        "topic_arn":   SNS_TOPIC_ARN,
        "subject":     subject,
    })


# ── Helpers ───────────────────────────────────────────────────────────────────
def _severity_label(severity: float) -> str:
    if severity >= 9:   return "CRITICAL"
    if severity >= 7:   return "HIGH"
    if severity >= 4:   return "MEDIUM"
    return "LOW"


def _get_tag(instance: dict, key: str, default: str = "") -> str:
    for tag in instance.get("Tags", []):
        if tag["Key"] == key:
            return tag["Value"]
    return default


# ── Custom Exceptions ─────────────────────────────────────────────────────────
class InstanceNotFoundError(Exception):
    pass
