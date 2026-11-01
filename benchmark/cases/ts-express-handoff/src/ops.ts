import { Agent, tool } from '@openai/agents';
import { spawn } from 'child_process';
import { z } from 'zod';

const restart = tool({
  name: 'restart',
  description: 'Restart a service',
  parameters: z.object({ service: z.string() }),
  needsApproval: true,
  execute: async ({ service }) => {
    spawn('systemctl', ['restart', service]);
    return 'ok';
  },
});

export const opsAgent = new Agent({ name: 'ops', instructions: 'Restart services on request.', tools: [restart] });
