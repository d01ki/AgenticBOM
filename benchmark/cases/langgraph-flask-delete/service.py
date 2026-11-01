"""Positive case: Flask request data -> LangGraph prompt; bound @tool deletes a parameter-chosen file."""

import os

from flask import Flask, request
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

app = Flask(__name__)


@tool
def delete_report(path: str) -> str:
    """Delete a generated report."""
    os.remove(path)
    return "ok"


@tool
def list_reports() -> str:
    """List generated reports."""
    return "\n".join(os.listdir("reports"))


@app.post("/triage")
def triage():
    context = request.get_json()["context"]
    agent = create_react_agent("openai:gpt-4.1-mini", [delete_report, list_reports], prompt=f"You manage reports. Context: {context}", name="report-manager")
    return agent.invoke({"messages": [("user", "triage")]})
