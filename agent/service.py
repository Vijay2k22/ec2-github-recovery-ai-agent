from config import SETTINGS
from incident_store import initialize, create_incident
from investigate import investigate
from mcp_client import connect_tools, call_tool, apache_evidence


async def prepare_incident(instance_id):
    if instance_id not in SETTINGS["instance_ids"]:
        raise ValueError("Instance is not allowed.")

    initialize()

    # Bedrock investigates and explains the available evidence.
    explanation = await investigate(instance_id)

    # Fresh tool evidence determines whether an approval can be offered.
    async with connect_tools() as session:
        state = await call_tool(
            session,
            "get_ec2_status",
            {"instance_id": instance_id},
        )

        health = await call_tool(session, "get_target_health", {})
        target = next(
            (
                item for item in health.get("targets", [])
                if item["instance_id"] == instance_id
            ),
            {},
        )

        evidence = {
            "explanation": explanation,
            "ec2": state,
            "target": target,
        }
        action = None

        if state["state"] == "stopped":
            action = "start_ec2_instance"

        elif (
            state["state"] == "running"
            and target.get("state") == "unhealthy"
        ):
            apache = await apache_evidence(session, instance_id)
            evidence["apache"] = apache

            output = apache.get("stdout", "")
            service_section = output.partition(
                "=== APACHE STATUS ==="
            )[2].partition("=== LOCAL HTTP ===")[0]

            service_states = {
                line.strip() for line in service_section.splitlines()
            }

            if (
                apache.get("status") == "Success"
                and service_states.intersection({"inactive", "failed"})
            ):
                action = "restart_apache"

    if not action:
        return {
            "incident_id": None,
            "explanation": explanation,
            "message": (
                "No supported recovery action is confirmed "
                "by the current diagnostic evidence."
            ),
        }

    incident_id = create_incident(instance_id, action, evidence)

    return {
        "incident_id": incident_id,
        "instance_id": instance_id,
        "action": action,
        "explanation": explanation,
        "message": "Recovery requires your approval.",
    }


async def execute_incident(incident_id):
    async with connect_tools() as session:
        return await call_tool(
            session,
            "execute_recovery",
            {"incident_id": incident_id},
        )


async def verify_incident(incident_id):
    async with connect_tools() as session:
        return await call_tool(
            session,
            "check_recovery",
            {"incident_id": incident_id},
        )