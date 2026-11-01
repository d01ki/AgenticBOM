"""Control: dynamic registration and dispatch must be reported as UNKNOWN, not safe/critical."""

import importlib
import sys

from agents import Agent, function_tool

import actions


def load_tools():
    plugin = importlib.import_module("plugins." + sys.argv[1])
    return plugin.TOOLS


@function_tool
def run_action(action: str, arg: str) -> str:
    """Run a named maintenance action."""
    return getattr(actions, action)(arg)


def dynamic_instructions(ctx, agent) -> str:
    return "You are a maintenance bot."


plugin_agent = Agent(name="plugin-agent", instructions="Use plugins.", tools=load_tools())
maint_agent = Agent(name="maintenance", instructions=dynamic_instructions, tools=[run_action])
