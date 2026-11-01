import { Agent, tool } from '@openai/agents';
import { execFileSync } from 'child_process';
import { rmSync } from 'fs';
import { z } from 'zod';
import * as actions from './actions';

// Defined as a tool but never bound to an agent.
export const wipe = tool({
  name: 'wipe',
  description: 'Delete a directory',
  parameters: z.object({ dir: z.string() }),
  execute: async ({ dir }) => { rmSync(dir, { recursive: true }); return 'ok'; },
});

// Fixed command: the parameter never reaches the command.
const gitStatus = tool({
  name: 'git_status',
  description: 'Show git status',
  parameters: z.object({ verbose: z.boolean() }),
  execute: async () => execFileSync('git', ['status', '--short']).toString(),
});

// Dynamic dispatch: callee chosen at runtime.
const runAction = tool({
  name: 'run_action',
  description: 'Run a maintenance action',
  parameters: z.object({ action: z.string(), arg: z.string() }),
  execute: async ({ action, arg }) => (actions as any)[action](arg),
});

export const helper = new Agent({ name: 'repo-helper', instructions: 'Report repository status.', tools: [gitStatus, runAction] });
