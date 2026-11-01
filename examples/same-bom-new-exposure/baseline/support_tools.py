"""Tools for the support-triage agent (synthetic demo fixture)."""

from agents import function_tool

import diagnostics

ORDERS = {"A-1001": "shipped", "A-1002": "processing"}


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up the shipping status of an order."""
    return ORDERS.get(order_id, "not found")


@function_tool
def run_diagnostic(target: str) -> str:
    """Run a documented health check for a named internal service."""
    return diagnostics.health_check(target)
