import json
import time

from config import SETTINGS, RULES
from incident_store import database
from recovery_executor import (
    aws_client,
    initialize_recovery,
    read_incident,
)


def save_verification(incident_id, verification):
    with database() as db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute(
            "SELECT status, result FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

        if not row or row["status"] != "executing":
            raise ValueError("Incident is not awaiting verification.")

        result = json.loads(row["result"] or "{}")
        result["verification"] = verification

        new_status = {
            "recovered": "recovered",
            "verification_failed": "verification_failed",
        }.get(verification["status"], "executing")

        db.execute("""
            UPDATE incidents
            SET status = ?, result = ?
            WHERE id = ? AND status = 'executing'
        """, (new_status, json.dumps(result), incident_id))


def verify_recovery(incident_id):
    """Check recovery once. Call again while status is verifying."""
    initialize_recovery()
    incident = read_incident(incident_id)

    if incident["status"] != "executing":
        raise ValueError("Incident is not awaiting verification.")

    execution = json.loads(incident["result"] or "{}")

    if execution.get("status") != "submitted":
        return {
            "status": "manual_review_required",
            "note": "Execution is uncertain or not recorded as submitted.",
        }

    instance_id = incident["instance_id"]

    if instance_id not in SETTINGS["instance_ids"]:
        raise ValueError("Instance is not allowed.")

    with database() as db:
        attempted_at = db.execute("""
            SELECT MAX(attempted_at) AS attempted_at
            FROM recovery_attempts
            WHERE incident_id = ?
        """, (incident_id,)).fetchone()["attempted_at"]

    if attempted_at is None:
        raise ValueError("No execution attempt is recorded.")

    expired = (
        time.time() - attempted_at
        >= RULES["verification_timeout_seconds"]
    )

    ec2 = aws_client("ec2")
    response = ec2.describe_instances(InstanceIds=[instance_id])
    instance = response["Reservations"][0]["Instances"][0]

    checks = ec2.describe_instance_status(
        InstanceIds=[instance_id],
        IncludeAllInstances=True,
    )["InstanceStatuses"]
    check = checks[0] if checks else {}

    targets = aws_client("elbv2").describe_target_health(
        TargetGroupArn=SETTINGS["target_group_arn"],
        Targets=[{"Id": instance_id, "Port": 80}],
    )["TargetHealthDescriptions"]

    target_state = (
        targets[0]["TargetHealth"]["State"]
        if targets else "unavailable"
    )

    ssm = aws_client("ssm")
    previous = execution.get("verification", {})
    command_id = previous.get("probe_command_id")

    # Submit one fixed read-only probe; reuse its ID on later checks.
    if instance["State"]["Name"] == "running" and not command_id:
        information = ssm.describe_instance_information(
            Filters=[{
                "Key": "InstanceIds",
                "Values": [instance_id],
            }]
        )["InstanceInformationList"]

        if information and information[0]["PingStatus"] == "Online":
            if not expired:
                # Persist a marker before sending, to avoid an
                # automatic resubmission after an ambiguous failure.
                if previous.get("probe_submission_started"):
                    return {
                        "status": "manual_review_required",
                        "note": "Probe submission result is uncertain.",
                    }

                save_verification(incident_id, {
                    "status": "verifying",
                    "probe_submission_started": True,
                })

                command = ssm.send_command(
                    InstanceIds=[instance_id],
                    DocumentName="AWS-RunShellScript",
                    Parameters={
                        "commands": [
                            "set -e\n"
                            "systemctl is-active --quiet httpd\n"
                            "code=$(curl --max-time 5 -s "
                            "-o /dev/null -w '%{http_code}' "
                            "http://localhost)\n"
                            'test "$code" = "200"\n'
                            "echo APACHE_HTTP_OK"
                        ],
                        "executionTimeout": ["15"],
                    },
                    TimeoutSeconds=30,
                    Comment="Read-only recovery verification",
                )
                command_id = command["Command"]["CommandId"]

    apache_http_ok = False
    probe_status = "not_submitted"

    if command_id:
        try:
            probe = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            probe_status = probe["Status"]
            apache_http_ok = (
                probe_status == "Success"
                and "APACHE_HTTP_OK"
                in probe.get("StandardOutputContent", "")
            )
        except ssm.exceptions.InvocationDoesNotExist:
            probe_status = "pending"

    healthy = (
        instance["State"]["Name"] == "running"
        and check.get("SystemStatus", {}).get("Status") == "ok"
        and check.get("InstanceStatus", {}).get("Status") == "ok"
        and target_state == "healthy"
        and apache_http_ok
    )

    result = {
        "status": (
            "recovered" if healthy else
            "verification_failed" if expired else "verifying"
        ),
        "instance_id": instance_id,
        "ec2_state": instance["State"]["Name"],
        "system_status": check.get("SystemStatus", {}).get("Status"),
        "instance_status": check.get("InstanceStatus", {}).get("Status"),
        "alb_target_health": target_state,
        "apache_http_ok": apache_http_ok,
        "probe_command_id": command_id,
        "probe_status": probe_status,
        "checked_at": time.time(),
    }

    save_verification(incident_id, result)
    return result