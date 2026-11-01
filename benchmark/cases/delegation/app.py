import sys

from agents import Agent, function_tool, handoff

from ops_agent import ops_agent


@function_tool
def save(path: str, text: str) -> str:
    """Save text."""
    with open(path, "w") as fh:
        fh.write(text)
    return "saved"


writer = Agent(name="writer", instructions="Write files.", model="gpt-4.1-mini", tools=[save])


def main() -> None:
    email = sys.stdin.read()
    triage = Agent(
        name="triage",
        instructions="Triage this email: " + email,
        model="gpt-4.1-mini",
        handoffs=[handoff(ops_agent)],
        tools=[writer.as_tool(tool_name="write_file", tool_description="Write a file")],
    )
    print(triage)
