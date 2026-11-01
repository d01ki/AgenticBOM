import subprocess

from agents import Agent, function_tool


@function_tool
def restart(service: str) -> str:
    """Restart a service."""
    subprocess.run(f"systemctl restart {service}", shell=True)
    return "ok"


ops_agent = Agent(name="ops", instructions="You restart services when asked.", model="gpt-4.1-mini", tools=[restart])
