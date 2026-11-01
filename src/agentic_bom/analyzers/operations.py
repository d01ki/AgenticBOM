"""Sensitive-operation recognisers (operation identification only — never permissions)."""

from __future__ import annotations

PROCESS_EXECUTION = "process_execution"
CODE_EXECUTION = "code_execution"
FILESYSTEM_WRITE = "filesystem_write"
FILESYSTEM_DELETE = "filesystem_delete"
NETWORK_STATE_CHANGE = "network_state_change"
CLOUD_SDK_CALL = "cloud_sdk_call"
SECRET_ACCESS = "secret_access"
DYNAMIC_DISPATCH = "dynamic_dispatch"  # unresolvable call target -> always UNKNOWN

CATEGORY_LABELS = {
    PROCESS_EXECUTION: "Process execution",
    CODE_EXECUTION: "Dynamic code execution",
    FILESYSTEM_WRITE: "Filesystem write",
    FILESYSTEM_DELETE: "Filesystem delete",
    NETWORK_STATE_CHANGE: "State-changing outbound HTTP",
    CLOUD_SDK_CALL: "Cloud SDK call",
    SECRET_ACCESS: "Secret / environment access",
    DYNAMIC_DISPATCH: "Unresolved dynamic call",
}

SINKS: dict[str, str] = {}
for _n in ("run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"):
    SINKS[f"subprocess.{_n}"] = PROCESS_EXECUTION
for _n in ("system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execlp", "execle", "spawnl", "spawnv", "spawnvp", "startfile", "posix_spawn"):
    SINKS[f"os.{_n}"] = PROCESS_EXECUTION
SINKS["asyncio.create_subprocess_shell"] = PROCESS_EXECUTION
SINKS["asyncio.create_subprocess_exec"] = PROCESS_EXECUTION
SINKS["builtins.eval"] = CODE_EXECUTION
SINKS["builtins.exec"] = CODE_EXECUTION
for _n in ("remove", "unlink", "rmdir", "removedirs"):
    SINKS[f"os.{_n}"] = FILESYSTEM_DELETE
SINKS["shutil.rmtree"] = FILESYSTEM_DELETE
for _n in ("copy", "copy2", "copyfile", "copytree", "move"):
    SINKS[f"shutil.{_n}"] = FILESYSTEM_WRITE
for _n in ("rename", "replace", "chmod", "chown"):
    SINKS[f"os.{_n}"] = FILESYSTEM_WRITE
for _lib in ("requests", "httpx"):
    for _m in ("post", "put", "patch", "delete"):
        SINKS[f"{_lib}.{_m}"] = NETWORK_STATE_CHANGE
SINKS["os.getenv"] = SECRET_ACCESS
SINKS["os.environ.get"] = SECRET_ACCESS
SINKS["os.getenvb"] = SECRET_ACCESS

OPEN_FUNCS = {"builtins.open", "io.open"}
GENERIC_REQUEST = {"requests.request", "httpx.request"}
CLOUD_FACTORIES = {"boto3.client", "boto3.resource", "boto3.session.Session.client"}
PATH_FACTORIES = {"pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath"}
PATH_METHODS = {
    "write_text": FILESYSTEM_WRITE,
    "write_bytes": FILESYSTEM_WRITE,
    "touch": FILESYSTEM_WRITE,
    "rename": FILESYSTEM_WRITE,
    "replace": FILESYSTEM_WRITE,
    "chmod": FILESYSTEM_WRITE,
    "unlink": FILESYSTEM_DELETE,
    "rmdir": FILESYSTEM_DELETE,
}
# boto3 read-only-looking verbs; everything else on a client is treated as a (possibly) state-changing call.
CLOUD_READ_PREFIXES = ("get_", "list_", "describe_", "head_", "generate_presigned")

# Which argument positions/keywords decide the operation *target*.
# None => every argument is target-relevant.
TARGET_ARGS: dict[str, tuple[tuple[int, ...], tuple[str, ...]]] = {
    FILESYSTEM_WRITE: ((0, 1), ("file", "path", "src", "dst", "dest", "destination")),
    FILESYSTEM_DELETE: ((0,), ("path",)),
    NETWORK_STATE_CHANGE: ((0,), ("url",)),
    SECRET_ACCESS: ((0,), ("key",)),
}
# keyword args that never carry attacker data
IGNORED_KWARGS = {"check", "text", "capture_output", "timeout", "encoding", "errors", "shell", "cwd_ok", "universal_newlines", "exist_ok"}
NETWORK_CONTENT_KWARGS = {"data", "json", "files", "content", "params", "headers"}


def match_function(qual: str | None) -> str | None:
    if not qual:
        return None
    return SINKS.get(qual)


# Library / built-in tools whose *documented* behaviour is a sensitive operation on model-supplied
# arguments. Their source is not analysed: edges built from this table are `inferred_limited`
# with scope `library_behaviour_model`.
LIBRARY_TOOLS: dict[str, str] = {}
for _p in ("langchain_community.tools", "langchain_community.tools.shell", "langchain_community.tools.shell.tool", "langchain.tools"):
    LIBRARY_TOOLS[f"{_p}.ShellTool"] = PROCESS_EXECUTION
for _p in ("langchain_experimental.tools", "langchain_experimental.tools.python.tool"):
    LIBRARY_TOOLS[f"{_p}.PythonREPLTool"] = CODE_EXECUTION
    LIBRARY_TOOLS[f"{_p}.PythonAstREPLTool"] = CODE_EXECUTION
for _p in ("langchain_community.tools", "langchain_community.tools.file_management"):
    LIBRARY_TOOLS[f"{_p}.WriteFileTool"] = FILESYSTEM_WRITE
    LIBRARY_TOOLS[f"{_p}.CopyFileTool"] = FILESYSTEM_WRITE
    LIBRARY_TOOLS[f"{_p}.MoveFileTool"] = FILESYSTEM_WRITE
    LIBRARY_TOOLS[f"{_p}.DeleteFileTool"] = FILESYSTEM_DELETE
for _p in ("langchain_community.tools", "langchain_community.tools.requests.tool"):
    for _v in ("Post", "Put", "Patch", "Delete"):
        LIBRARY_TOOLS[f"{_p}.Requests{_v}Tool"] = NETWORK_STATE_CHANGE
for _p in ("agents", "agents.tool"):
    LIBRARY_TOOLS[f"{_p}.LocalShellTool"] = PROCESS_EXECUTION
    LIBRARY_TOOLS[f"{_p}.ShellTool"] = PROCESS_EXECUTION

# Provider-hosted tools: executed by the model provider, not on the application host.
HOSTED_TOOLS = {f"agents.{n}" for n in ("WebSearchTool", "FileSearchTool", "CodeInterpreterTool", "ImageGenerationTool")}
HOSTED_TOOLS |= {f"agents.tool.{n}" for n in ("WebSearchTool", "FileSearchTool", "CodeInterpreterTool", "ImageGenerationTool")}
# ShellTool(environment={"type": ...}) values that run in a provider-hosted container
HOSTED_SHELL_ENVIRONMENTS = {"container_auto", "container_reference"}

# Toolkits expanded via `.get_tools()`: toolkit -> {tool name: library tool qual}
LIBRARY_TOOLKITS: dict[str, dict[str, str]] = {}
_FM = {
    "write_file": "langchain_community.tools.WriteFileTool",
    "copy_file": "langchain_community.tools.CopyFileTool",
    "move_file": "langchain_community.tools.MoveFileTool",
    "file_delete": "langchain_community.tools.DeleteFileTool",
    "read_file": "",
    "list_directory": "",
    "file_search": "",
}
for _p in ("langchain_community.agent_toolkits", "langchain_community.agent_toolkits.file_management.toolkit", "langchain.agents.agent_toolkits"):
    LIBRARY_TOOLKITS[f"{_p}.FileManagementToolkit"] = _FM
