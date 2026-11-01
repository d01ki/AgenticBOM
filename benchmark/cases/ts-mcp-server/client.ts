import { Agent, MCPServerStdio, run } from '@openai/agents';

const notes = new MCPServerStdio({ name: 'notes', command: 'npx', args: ['tsx', 'server.ts'] });

export const assistant = new Agent({
  name: 'notes-assistant',
  instructions: 'Help the user manage notes.',
  model: 'gpt-4.1-mini',
  mcpServers: [notes],
});

await run(assistant, process.argv[2]);
