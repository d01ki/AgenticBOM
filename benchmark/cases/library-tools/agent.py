from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools import ShellTool
from langgraph.prebuilt import create_react_agent

files = FileManagementToolkit(root_dir="/srv/work", selected_tools=["read_file", "write_file"])

ops = create_react_agent("openai:gpt-4.1-mini", [ShellTool()] + files.get_tools(), prompt="You are a DevOps helper.", name="devops")
