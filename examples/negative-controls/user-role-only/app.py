"""Control: untrusted input stays in the user-role message; instructions are static."""

import os
import sys

from agents import Agent, Runner, function_tool


@function_tool
def delete_upload(path: str) -> str:
    """Delete an uploaded file."""
    os.remove(path)
    return "deleted"


def main() -> None:
    message = sys.stdin.read()
    agent = Agent(name="upload-janitor", instructions="Clean up uploads when asked.", model="gpt-4.1-mini", tools=[delete_upload])
    Runner.run_sync(agent, message)
