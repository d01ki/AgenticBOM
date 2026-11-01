import shutil


def clean(path: str) -> None:
    shutil.rmtree(path)
