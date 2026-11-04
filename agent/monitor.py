import asyncio
import logging
import time

from config import SETTINGS, RULES
from incident_store import database, initialize
from recovery_executor import aws_client
from service import prepare_incident

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def initialize_monitor():
    initialize()

    with database() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS monitor_state (
                instance_id TEXT PRIMARY KEY,
                failures INTEGER NOT NULL DEFAULT 0,
                investigated INTEGER NOT NULL DEFAULT 0,
                healthy_since REAL
            )
        """)

        for instance_id in SETTINGS["instance_ids"]:
            db.execute("""
                INSERT OR IGNORE INTO monitor_state(instance_id)
                VALUES (?)
            """, (instance_id,))


def should_investigate(instance_id, healthy, abnormal, permitted):
    now = time.time()

    with database() as db:
        db.execute("BEGIN IMMEDIATE")

        row = db.execute("""
            SELECT * FROM monitor_state WHERE instance_id = ?
        """, (instance_id,)).fetchone()

        if healthy:
            since = row["healthy_since"] or now
            reset = now - since >= RULES["cooldown_seconds"]

            db.execute("""
                UPDATE monitor_state
                SET failures = 0,
                    healthy_since = ?,
                    investigated = ?
                WHERE instance_id = ?
            """, (
                since,
                0 if reset else row["investigated"],
                instance_id,
            ))
            return False

        failures = row["failures"] + 1 if abnormal else 0

        trigger = (
            abnormal
            and permitted
            and failures >= 2
            and not row["investigated"]
        )

        db.execute("""
            UPDATE monitor_state
            SET failures = ?, healthy_since = NULL,
                investigated = ?
            WHERE instance_id = ?
        """, (
            failures,
            1 if trigger else row["investigated"],
            instance_id,
        ))

        # Persist before calling Bedrock to prevent repeated investigations.
        return trigger


async def monitor_once():
    response = await asyncio.to_thread(
        aws_client("ec2").describe_instances,
        InstanceIds=SETTINGS["instance_ids"],
    )

    health = await asyncio.to_thread(
        aws_client("elbv2").describe_target_health,
        TargetGroupArn=SETTINGS["target_group_arn"],
    )

    targets = {
        item["Target"]["Id"]: item["TargetHealth"]["State"]
        for item in health["TargetHealthDescriptions"]
    }

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instance_id = instance["InstanceId"]
            state = instance["State"]["Name"]
            target = targets.get(instance_id, "unavailable")
            tags = {
                tag["Key"]: tag["Value"]
                for tag in instance.get("Tags", [])
            }

            permitted = all(
                tags.get(key) == value
                for key, value in RULES["required_tags"].items()
            )

            healthy = state == "running" and target == "healthy"
            abnormal = (
                state == "stopped"
                or (state == "running" and target == "unhealthy")
            )

            logging.info(
                "%s: EC2=%s ALB=%s eligible=%s",
                instance_id, state, target, permitted,
            )

            if should_investigate(
                instance_id, healthy, abnormal, permitted
            ):
                try:
                    result = await prepare_incident(instance_id)
                    logging.info("Investigation result: %s", result["message"])

                    if result.get("incident_id"):
                        logging.info(
                            "Incident %s awaits operator approval",
                            result["incident_id"],
                        )
                except Exception:
                    logging.exception(
                        "Investigation failed for %s. "
                        "Use manual investigation in the chat.",
                        instance_id,
                    )


async def main():
    initialize_monitor()

    while True:
        started = time.monotonic()

        try:
            await monitor_once()
        except Exception:
            logging.exception("Monitoring cycle failed")

        elapsed = time.monotonic() - started
        await asyncio.sleep(
            max(1, SETTINGS["poll_interval_seconds"] - elapsed)
        )


if __name__ == "__main__":
    asyncio.run(main())