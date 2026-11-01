"""Support triage agent (synthetic demo fixture)."""

import sys

from agents import Agent, Runner

from support_tools import lookup_order, run_diagnostic

BASE_INSTRUCTIONS = (
    "You are a support triage agent. Use lookup_order for order questions and "
    "run_diagnostic only for documented health checks."
)


def build_agent(ticket: str) -> Agent:
    return Agent(
        name="support-triage",
        # Candidate: the untrusted ticket is pasted into the privileged instructions.
        instructions=f"{BASE_INSTRUCTIONS}\n\nCustomer ticket:\n{ticket}",
        model="gpt-4.1-mini",
        tools=[lookup_order, run_diagnostic],
    )


def main() -> None:
    ticket = sys.stdin.read()
    agent = build_agent(ticket)
    result = Runner.run_sync(agent, "Triage the ticket in your instructions.")
    print(result.final_output)


if __name__ == "__main__":
    main()
