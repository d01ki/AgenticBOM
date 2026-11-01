"""Control: untrusted instructions + a guard implemented by an unsupported validator -> UNKNOWN."""

import subprocess
import sys

from agents import Agent, function_tool

from validators import is_safe_command


@function_tool
def run(cmd: str) -> str:
    """Run an approved command."""
    if not is_safe_command(cmd):
        return "rejected"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def main() -> None:
    note = sys.stdin.read()
    Agent(name="guarded-runner", instructions="Operator note: " + note, model="gpt-4.1-mini", tools=[run])
