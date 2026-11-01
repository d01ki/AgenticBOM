from agents import Agent

from pkg.tools import write_deep, write_record

recorder = Agent(name="recorder", instructions="Store records.", model="gpt-4.1-mini", tools=[write_record, write_deep])
