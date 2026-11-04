import asyncio
import sys
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from investigate import tool_data


@asynccontextmanager
async def connect_tools():
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
            yield session


async def call_tool(session, name, arguments):
    result = await session.call_tool(name, arguments)

    if result.isError:
        raise RuntimeError(str(result.model_dump(mode="json")))

    return tool_data(result)


async def apache_evidence(session, instance_id):
    submitted = await call_tool(
        session,
        "collect_apache_diagnostics",
        {"instance_id": instance_id},
    )

    command_id = submitted.get("command_id")
    if not command_id:
        return submitted

    for attempt in range(15):
        await asyncio.sleep(3)

        result = await call_tool(
            session,
            "get_diagnostic_result",
            {
                "instance_id": instance_id,
                "command_id": command_id,
            },
        )

        if result.get("status") in {
            "Success", "Failed", "Cancelled", "TimedOut"
        }:
            return result

    return {"status": "diagnostic_timeout"}