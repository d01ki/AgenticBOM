from pkg.paths import resolve


def save(name: str, data: str) -> None:
    with open(resolve(name), "w") as fh:
        fh.write(data)


def save_deep(name: str, data: str) -> None:
    level2(name, data)


def level2(name: str, data: str) -> None:
    level3(name, data)


def level3(name: str, data: str) -> None:
    level4(name, data)


def level4(name: str, data: str) -> None:
    open(name, "a").write(data)
