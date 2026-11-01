// Tools for the support-triage agent (synthetic demo fixture).
import { tool } from '@openai/agents';
import { z } from 'zod';
import { healthCheck } from './diagnostics';

const ORDERS: Record<string, string> = { 'A-1001': 'shipped', 'A-1002': 'processing' };

export const lookupOrder = tool({
  name: 'lookup_order',
  description: 'Look up the shipping status of an order.',
  parameters: z.object({ orderId: z.string() }),
  execute: async ({ orderId }) => ORDERS[orderId] ?? 'not found',
});

export const runDiagnostic = tool({
  name: 'run_diagnostic',
  description: 'Run a documented health check for a named internal service.',
  parameters: z.object({ target: z.string() }),
  execute: async ({ target }: { target: string }) => healthCheck(target),
});
