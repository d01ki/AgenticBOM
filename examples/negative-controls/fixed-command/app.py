"""Negative control: bound tool runs a FIXED command; no parameter reaches it."""

import subprocess

from agents import Agent, function_tool


@function_tool
def repo_status(verbose: bool = False) -> str:
    """Show git status of the service repository."""
    out = subprocess.run(["git", "status", "--short"], capture_output=True, text=True, check=False)
    return out.stdout


ops_agent = Agent(name="repo-helper", instructions="Report repository status.", model="gpt-4.1-mini", tools=[repo_status])
