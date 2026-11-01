"""Positive case: FastAPI route parameter -> instructions; eval and boto3 delete reachable."""

import boto3
from agents import Agent, Runner, function_tool
from fastapi import FastAPI

api = FastAPI()
s3 = boto3.client("s3")
BUCKET = "customer-exports"


@function_tool
def calculate(expression: str) -> str:
    """Evaluate an arithmetic expression."""
    return str(eval(expression))


@function_tool
def remove_export(key: str) -> str:
    """Remove an export object."""
    s3.delete_object(Bucket=BUCKET, Key=key)
    return "removed"


@function_tool
def export_count() -> int:
    """Count exports (read-only)."""
    return len(s3.list_objects_v2(Bucket=BUCKET).get("Contents", []))


@api.post("/ask")
async def ask(question: str):
    agent = Agent(
        name="export-assistant",
        instructions=f"Answer this account question: {question}",
        model="gpt-4.1",
        tools=[calculate, remove_export, export_count],
    )
    return (await Runner.run(agent, "go")).final_output
