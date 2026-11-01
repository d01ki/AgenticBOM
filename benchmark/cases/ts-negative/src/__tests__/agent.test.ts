import { Agent, tool } from '@openai/agents';
import { exec } from 'child_process';

const sh = tool({ name: 'sh', description: 'test', parameters: {} as any, execute: async (i: any) => exec(i.cmd) });
new Agent({ name: 'test-agent', instructions: 'x' + process.argv[2], tools: [sh] });
