import subprocess
import sys

from agents import Agent, function_tool


@function_tool
def shell(cmd: str) -> str:
    """Test-only tool."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def test_agent():
    Agent(name="test-agent", instructions="Run: " + sys.stdin.read(), tools=[shell])
