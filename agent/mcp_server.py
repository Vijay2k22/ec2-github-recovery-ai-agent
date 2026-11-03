import boto3
from botocore.config import Config
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta, timezone

from config import SETTINGS

mcp = FastMCP("EC2 Recovery Tools")


def aws_client(service):
    timeout = SETTINGS["aws_api_timeout_seconds"]
    return boto3.client(
        service,
        region_name=SETTINGS["aws_region"],
        config=Config(
            connect_timeout=timeout,
            read_timeout=timeout,
            retries={"mode": "standard", "total_max_attempts": 3},
        ),
    )


def validate_instance(instance_id):
    if instance_id not in SETTINGS["instance_ids"]:
        raise ValueError("Instance is not in the configured allowlist.")


@mcp.tool()
def get_ec2_status(instance_id: str) -> dict:
    """Read state, tags, and status checks for an allowed instance."""
    validate_instance(instance_id)
    ec2 = aws_client("ec2")

    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response["Reservations"][0]["Instances"][0]

    checks = ec2.describe_instance_status(
        InstanceIds=[instance_id],
        IncludeAllInstances=True,
    )["InstanceStatuses"]

    check = checks[0] if checks else {}

    return {
        "instance_id": instance_id,
        "state": instance["State"]["Name"],
        "tags": {
            tag["Key"]: tag["Value"]
            for tag in instance.get("Tags", [])
        },
        "system_status": check.get(
            "SystemStatus", {}
        ).get("Status", "unavailable"),
        "instance_status": check.get(
            "InstanceStatus", {}
        ).get("Status", "unavailable"),
    }


@mcp.tool()
def get_target_health() -> dict:
    """Read ALB target health for the configured demo instances."""
    response = aws_client("elbv2").describe_target_health(
        TargetGroupArn=SETTINGS["target_group_arn"]
    )

    targets = []
    for item in response["TargetHealthDescriptions"]:
        instance_id = item["Target"]["Id"]
        if instance_id not in SETTINGS["instance_ids"]:
            continue

        health = item["TargetHealth"]
        targets.append({
            "instance_id": instance_id,
            "state": health["State"],
            "reason": health.get("Reason", ""),
            "description": health.get("Description", ""),
        })

    return {"targets": targets}

@mcp.tool()
def get_cloudwatch_metrics(instance_id: str) -> dict:
    """Read the last 30 minutes of EC2 CPU and status-check metrics."""
    validate_instance(instance_id)
    cloudwatch = aws_client("cloudwatch")
    end = datetime.now(timezone.utc)
    metrics = {}

    for name in ["CPUUtilization", "StatusCheckFailed"]:
        response = cloudwatch.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName=name,
            Dimensions=[
                {"Name": "InstanceId", "Value": instance_id}
            ],
            StartTime=end - timedelta(minutes=30),
            EndTime=end,
            Period=300,
            Statistics=["Average", "Maximum"],
        )

        points = sorted(
            response["Datapoints"],
            key=lambda point: point["Timestamp"],
        )

        metrics[name] = [
            {
                "timestamp": point["Timestamp"].isoformat(),
                "average": point["Average"],
                "maximum": point["Maximum"],
            }
            for point in points
        ]

    return {
        "instance_id": instance_id,
        "metrics": metrics,
        "note": "Missing or delayed metrics are not proof of health.",
    }


@mcp.tool()
def get_recent_events(instance_id: str) -> dict:
    """Read recent CloudTrail management events for an allowed instance."""
    validate_instance(instance_id)
    end = datetime.now(timezone.utc)

    response = aws_client("cloudtrail").lookup_events(
        LookupAttributes=[
            {
                "AttributeKey": "ResourceName",
                "AttributeValue": instance_id,
            }
        ],
        StartTime=end - timedelta(hours=2),
        EndTime=end,
        MaxResults=20,
    )

    return {
        "instance_id": instance_id,
        "events": [
            {
                "event": event["EventName"],
                "time": event["EventTime"].isoformat(),
                "user": event.get("Username", "unknown"),
                "source": event.get("EventSource", ""),
            }
            for event in response["Events"]
        ],
        "more_available": bool(response.get("NextToken")),
        "note": "Events may be delayed. An empty result is inconclusive.",
    }


@mcp.tool()
def collect_apache_diagnostics(instance_id: str) -> dict:
    """Submit fixed read-only Apache checks through SSM. Returns command ID."""
    validate_instance(instance_id)

    if get_ec2_status(instance_id)["state"] != "running":
        return {
            "instance_id": instance_id,
            "error": "Instance is not running. SSM checks cannot execute.",
        }

    script = """
echo '=== APACHE STATUS ==='
systemctl is-active httpd || true
echo '=== LOCAL HTTP ==='
curl --max-time 5 -s -o /dev/null -w '%{http_code}\\n' http://localhost || true
echo '=== RECENT SERVICE LOG ==='
journalctl -u httpd -n 25 --no-pager || true
echo '=== APACHE ERROR LOG ==='
tail -n 25 /var/log/httpd/error_log 2>/dev/null || true
"""

    response = aws_client("ssm").send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={
            "commands": [script],
            "executionTimeout": ["30"],
        },
        TimeoutSeconds=30,
        Comment="AI agent read-only Apache diagnostics",
    )

    return {
        "instance_id": instance_id,
        "command_id": response["Command"]["CommandId"],
        "status": "submitted",
    }


@mcp.tool()
def get_diagnostic_result(instance_id: str, command_id: str) -> dict:
    """Read SSM output for a diagnostic command on an allowed instance."""
    validate_instance(instance_id)
    ssm = aws_client("ssm")

    try:
        response = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
    except ssm.exceptions.InvocationDoesNotExist:
        return {
            "status": "not_available_yet",
            "note": "Wait briefly before checking again.",
        }

    return {
        "instance_id": instance_id,
        "command_id": command_id,
        "status": response["Status"],
        "stdout": response.get("StandardOutputContent", "")[:8000],
        "stderr": response.get("StandardErrorContent", "")[:2000],
    }

if __name__ == "__main__":
    mcp.run(transport="stdio")