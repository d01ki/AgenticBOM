"""Notes assistant connecting to the local MCP server (synthetic demo fixture)."""

import asyncio
import sys

from agents import Agent, Runner
from agents.mcp import MCPServerStdio


async def main() -> None:
    request = sys.stdin.read()
    async with MCPServerStdio(params={"command": "python", "args": ["server.py"]}) as notes_server:
        agent = Agent(
            name="notes-assistant",
            instructions="Help the user manage their notes.",
            model="gpt-4.1-mini",
            mcp_servers=[notes_server],
        )
        result = await Runner.run(agent, request)
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
