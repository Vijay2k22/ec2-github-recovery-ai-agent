import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path

import boto3
from botocore.config import Config
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from config import SETTINGS, RULES, SYSTEM_PROMPT


def tool_data(result):
    """Extract a dictionary from an MCP tool result."""
    if isinstance(result.structuredContent, dict):
        return result.structuredContent

    for block in result.content:
        if block.type == "text":
            try:
                data = json.loads(block.text)
            except (ValueError, TypeError):
                continue

            if isinstance(data, dict):
                return data

    return {}


async def execute_diagnostic(session, name, arguments, instance_id):
    result = await session.call_tool(name, arguments)

    if result.isError:
        return result.model_dump(mode="json"), "error"

    if name != "collect_apache_diagnostics":
        return result.model_dump(mode="json"), "success"

    data = tool_data(result)
    command_id = data.get("command_id")

    if not command_id:
        return {
            "status": "diagnostics_not_submitted",
            "details": data,
        }, "error"

    for attempt in range(15):
        await asyncio.sleep(3)

        check = await session.call_tool(
            "get_diagnostic_result",
            {
                "instance_id": instance_id,
                "command_id": command_id,
            },
        )

        if check.isError:
            return check.model_dump(mode="json"), "error"

        command_status = tool_data(check).get("status")

        if command_status in {
            "Success", "Failed", "Cancelled", "TimedOut"
        }:
            status = "success" if command_status == "Success" else "error"
            return check.model_dump(mode="json"), status

    return {
        "command_id": command_id,
        "status": "diagnostic_result_timeout",
        "note": (
            "Diagnostic result was not available in time. "
            "Do not claim Apache health is verified."
        ),
    }, "error"


async def investigate(instance_id):
    if instance_id not in SETTINGS["instance_ids"]:
        raise ValueError("Instance is not allowed.")

    bedrock = boto3.client(
        "bedrock-runtime",
        region_name=SETTINGS["bedrock_region"],
        config=Config(
            connect_timeout=10,
            read_timeout=SETTINGS["bedrock_timeout_seconds"],
            retries={"mode": "standard", "total_max_attempts": 2},
        ),
    )

    server = StdioServerParameters(
        command=sys.executable,
        args=[
            str(Path(__file__).with_name("mcp_server.py").resolve())
        ],
    )

    async with stdio_client(server) as (read, write):
        async with ClientSession(
            read,
            write,
            read_timeout_seconds=timedelta(seconds=90),
        ) as session:
            await session.initialize()
            discovered = await session.list_tools()

            permitted = {
                "get_ec2_status",
                "get_target_health",
                "get_cloudwatch_metrics",
                "get_recent_events",
                "collect_apache_diagnostics",
                "get_diagnostic_result",
            }

            tools = [
                {
                    "toolSpec": {
                        "name": tool.name,
                        "description": tool.description or tool.name,
                        "inputSchema": {"json": tool.inputSchema},
                    }
                }
                for tool in discovered.tools
                if tool.name in permitted
            ]

            messages = [{
                "role": "user",
                "content": [{
                    "text": (
                        f"Investigate instance {instance_id}. "
                        "Check its state and ALB health first. "
                        "Collect further evidence when needed. "
                        "The collect_apache_diagnostics tool response "
                        "includes the collected result when available. "
                        "Do not diagnose another instance. "
                        "Recommend a permitted action only if justified. "
                        "Do not perform recovery. "
                        "Finish with findings rather than internal thoughts. "
                        f"Allowed actions: {RULES['allowed_actions']}."
                    )
                }],
            }]

            for step in range(RULES["max_investigation_steps"]):
                response = await asyncio.to_thread(
                    bedrock.converse,
                    modelId=SETTINGS["bedrock_model_id"],
                    system=[{"text": SYSTEM_PROMPT}],
                    messages=messages,
                    toolConfig={"tools": tools},
                    inferenceConfig={
                        "maxTokens": SETTINGS["max_output_tokens"],
                        "temperature": SETTINGS["temperature"],
                    },
                )

                message = response["output"]["message"]
                messages.append(message)

                calls = [
                    block["toolUse"]
                    for block in message["content"]
                    if "toolUse" in block
                ]

                if response["stopReason"] == "end_turn" and not calls:
                    return "\n".join(
                        block["text"]
                        for block in message["content"]
                        if "text" in block
                    )

                if response["stopReason"] != "tool_use" or not calls:
                    return (
                        "Investigation incomplete. "
                        f"Model stopped with: {response['stopReason']}. "
                        "No recovery executed."
                    )

                results = []

                for call in calls:
                    name = call["name"]
                    arguments = call["input"]
                    print(f"Diagnostic tool: {name}", flush=True)

                    try:
                        if name not in permitted:
                            raise ValueError("Tool is not permitted.")

                        if (
                            "instance_id" in arguments
                            and arguments["instance_id"] != instance_id
                        ):
                            raise ValueError("Incident target mismatch.")

                        if name == "get_diagnostic_result":
                            await asyncio.sleep(3)

                        payload, status = await execute_diagnostic(
                            session, name, arguments, instance_id
                        )

                    except Exception as error:
                        payload = {"error": str(error)}
                        status = "error"

                    results.append({
                        "toolResult": {
                            "toolUseId": call["toolUseId"],
                            "content": [{"text": json.dumps(payload)}],
                            "status": status,
                        }
                    })

                messages.append({
                    "role": "user",
                    "content": results,
                })

            return (
                "Investigation step limit reached. "
                "Manual review required. No recovery executed."
            )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python investigate.py <instance-id>")

    print(asyncio.run(investigate(sys.argv[1])))