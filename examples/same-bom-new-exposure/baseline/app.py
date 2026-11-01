"""Support triage agent (synthetic demo fixture)."""

import sys

from agents import Agent, Runner

from support_tools import lookup_order, run_diagnostic

BASE_INSTRUCTIONS = (
    "You are a support triage agent. Use lookup_order for order questions and "
    "run_diagnostic only for documented health checks."
)


def build_agent() -> Agent:
    return Agent(
        name="support-triage",
        instructions=BASE_INSTRUCTIONS,
        model="gpt-4.1-mini",
        tools=[lookup_order, run_diagnostic],
    )


def main() -> None:
    ticket = sys.stdin.read()
    agent = build_agent()
    # The untrusted ticket stays in the user-role message.
    result = Runner.run_sync(agent, ticket)
    print(result.final_output)


if __name__ == "__main__":
    main()
