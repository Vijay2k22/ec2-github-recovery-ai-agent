import asyncio
import sys
from datetime import timedelta
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    server_path = Path(__file__).resolve().with_name("mcp_server.py")

    parameters = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)],
    )

    async with stdio_client(parameters) as (read, write):
        async with ClientSession(
            read,
            write,
            read_timeout_seconds=timedelta(seconds=30),
        ) as session:
            await session.initialize()
            result = await session.list_tools()

            print("\nMCP connection successful.")
            print("Available tools:")
            for tool in result.tools:
                print(f"- {tool.name}")


if __name__ == "__main__":
    asyncio.run(main())