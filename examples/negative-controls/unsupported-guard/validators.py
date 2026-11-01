import shlex


def is_safe_command(cmd: str) -> bool:
    return shlex.split(cmd)[0] in {"uptime", "df"}
