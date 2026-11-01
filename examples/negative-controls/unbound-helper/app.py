"""Negative control: dangerous code exists but is NOT bound to the agent."""

import os
import shutil
from datetime import datetime, timezone

from agents import Agent, function_tool


@function_tool
def get_time() -> str:
    """Return the current UTC time."""
    return datetime.now(timezone.utc).isoformat()


@function_tool
def wipe_cache(path: str) -> str:
    """Delete a cache directory. Defined as a tool but never bound to an agent."""
    shutil.rmtree(path)
    return "wiped"


def purge(path: str) -> None:
    os.remove(path)


clock = Agent(name="clock", instructions="Tell the time.", model="gpt-4.1-mini", tools=[get_time])
