"""Operator CLI (not an agent). Calls a dangerous helper directly."""

import sys

from diagnostics import restart_service

if __name__ == "__main__":
    restart_service(sys.argv[1])
