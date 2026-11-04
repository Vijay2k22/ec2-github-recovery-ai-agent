import json
import time

import boto3
from botocore.config import Config

from config import SETTINGS, RULES
from incident_store import database, initialize


def aws_client(service):
    timeout = SETTINGS["aws_api_timeout_seconds"]
    return boto3.client(
        service,
        region_name=SETTINGS["aws_region"],
        config=Config(
            connect_timeout=timeout,
            read_timeout=timeout,
            # Do not automatically repeat a recovery request.
            retries={"mode": "standard", "total_max_attempts": 1},
        ),
    )


def initialize_recovery():
    initialize()

    with database() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS recovery_attempts (
                incident_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                action TEXT NOT NULL,
                attempted_at REAL NOT NULL
            )
        """)


def read_incident(incident_id):
    with database() as db:
        row = db.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()

    if not row:
        raise ValueError("Incident does not exist.")

    return dict(row)


def validate_target(incident):
    instance_id = incident["instance_id"]
    action = incident["action"]

    if instance_id not in SETTINGS["instance_ids"]:
        raise ValueError("Instance is not allowed.")

    if action not in RULES["allowed_actions"]:
        raise ValueError("Action is not allowed.")

    response = aws_client("ec2").describe_instances(
        InstanceIds=[instance_id]
    )
    instance = response["Reservations"][0]["Instances"][0]
    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get("Tags", [])
    }

    for key, expected in RULES["required_tags"].items():
        if tags.get(key) != expected:
            raise ValueError(
                f"Safety check failed: tag {key} must be {expected}."
            )

    state = instance["State"]["Name"]

    if action == "start_ec2_instance" and state != "stopped":
        raise ValueError("Start action requires a stopped instance.")

    if action == "restart_apache":
        if state != "running":
            raise ValueError("Apache restart requires a running instance.")

        information = aws_client("ssm").describe_instance_information(
            Filters=[{
                "Key": "InstanceIds",
                "Values": [instance_id],
            }]
        )["InstanceInformationList"]

        if not information or information[0]["PingStatus"] != "Online":
            raise ValueError("Instance is not Online in SSM.")


def claim_approval(incident):
    now = time.time()

    with database() as db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident["id"],),
        ).fetchone()

        if not row or row["status"] != "approved":
            raise ValueError("A valid recorded approval is required.")

        if row["expires_at"] <= now:
            raise ValueError("Approval has expired.")

        if (
            row["instance_id"] != incident["instance_id"]
            or row["action"] != incident["action"]
        ):
            raise ValueError("Approved target or action changed.")

        if row["attempts"] >= RULES["max_recovery_attempts_per_incident"]:
            raise ValueError("Recovery attempt limit reached.")

        last = db.execute("""
            SELECT MAX(attempted_at) AS last_attempt
            FROM recovery_attempts
            WHERE instance_id = ?
        """, (row["instance_id"],)).fetchone()["last_attempt"]

        if last is not None and now - last < RULES["cooldown_seconds"]:
            raise ValueError("Recovery cooldown is active.")

        db.execute("""
            UPDATE incidents
            SET status = 'executing', attempts = attempts + 1
            WHERE id = ? AND status = 'approved'
        """, (row["id"],))

        db.execute("""
            INSERT INTO recovery_attempts (
                incident_id, instance_id, action, attempted_at
            ) VALUES (?, ?, ?, ?)
        """, (
            row["id"], row["instance_id"], row["action"], now,
        ))


def save_execution_result(incident_id, result):
    with database() as db:
        db.execute("""
            UPDATE incidents
            SET result = ?
            WHERE id = ? AND status = 'executing'
        """, (json.dumps(result), incident_id))


def execute_approved_recovery(incident_id):
    initialize_recovery()
    incident = read_incident(incident_id)

    # Validate current AWS state before consuming approval.
    validate_target(incident)

    # Transaction prevents two workers using the same approval.
    claim_approval(incident)

    instance_id = incident["instance_id"]
    action = incident["action"]

    try:
        if action == "start_ec2_instance":
            response = aws_client("ec2").start_instances(
                InstanceIds=[instance_id]
            )

            result = {
                "status": "submitted",
                "action": action,
                "instance_id": instance_id,
                "aws_request_id": response["ResponseMetadata"]["RequestId"],
            }

        elif action == "restart_apache":
            response = aws_client("ssm").send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={
                    "commands": ["systemctl restart httpd"],
                    "executionTimeout": ["30"],
                },
                TimeoutSeconds=30,
                Comment=f"Approved recovery {incident_id}",
            )

            result = {
                "status": "submitted",
                "action": action,
                "instance_id": instance_id,
                "command_id": response["Command"]["CommandId"],
            }

        save_execution_result(incident_id, result)
        return result

    except Exception as error:
        # A timeout can happen after AWS accepted the request.
        # Keep the incident locked against duplicate recovery.
        result = {
            "status": "execution_uncertain",
            "action": action,
            "instance_id": instance_id,
            "error": str(error),
            "note": "Check AWS state before any manual retry.",
        }

        save_execution_result(incident_id, result)
        return result