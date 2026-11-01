from agents import Agent, function_tool

from storage import Storage

store = Storage()


@function_tool
def remove_export(key: str) -> str:
    """Remove an export object."""
    Storage().delete(key)
    return "ok"


@function_tool
def purge_dir(path: str) -> str:
    """Purge a work directory."""
    s = Storage()
    s.purge(path)
    return "ok"


cleaner = Agent(name="cleaner", instructions="Clean up storage.", model="gpt-4.1-mini", tools=[remove_export, purge_dir])
