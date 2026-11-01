import express from 'express';
import { Agent, run, tool } from '@openai/agents';
import { z } from 'zod';
import { opsAgent } from './ops';
import { Storage } from './storage';

const app = express();

const cleanup = tool({
  name: 'cleanup_export',
  description: 'Delete an export object',
  parameters: z.object({ key: z.string() }),
  execute: async (input) => {
    const store = new Storage();
    await store.remove(input.key);
    return 'deleted';
  },
});

app.post('/triage', async (req, res) => {
  const agent = new Agent({
    name: 'triage',
    instructions: 'Handle this customer note: ' + req.body.note,
    model: 'gpt-4.1',
    handoffs: [opsAgent],
    tools: [cleanup],
  });
  const result = await run(agent, 'go');
  res.json({ out: result.finalOutput });
});

app.listen(3000);
