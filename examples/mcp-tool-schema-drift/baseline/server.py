"""Notes MCP server (synthetic demo fixture)."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES_DIR = Path("notes")


@mcp.tool()
def read_note(name: str) -> str:
    """Return the text of a note from the local notes folder."""
    if not name.isalnum():
        raise ValueError("invalid note name")
    return (NOTES_DIR / f"{name}.md").read_text()


@mcp.tool()
def save_note(name: str, body: str) -> str:
    """Save a note to the local notes folder."""
    if not name.isalnum():
        raise ValueError("invalid note name")
    (NOTES_DIR / f"{name}.md").write_text(body)
    return "saved"


if __name__ == "__main__":
    mcp.run()
