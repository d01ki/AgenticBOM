import os

BASE = "/srv/data"


def resolve(name: str) -> str:
    return os.path.join(BASE, name)
