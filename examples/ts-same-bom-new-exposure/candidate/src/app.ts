// Support triage agent (synthetic demo fixture).
import { Agent, run } from '@openai/agents';
import { readFileSync } from 'node:fs';
import { lookupOrder, runDiagnostic } from './tools';

const BASE_INSTRUCTIONS =
  'You are a support triage agent. Use lookup_order for order questions and run_diagnostic only for documented health checks.';

export function buildAgent(ticket: string): Agent {
  return new Agent({
    name: 'support-triage',
    // Candidate: the untrusted ticket is pasted into the privileged instructions.
    instructions: `${BASE_INSTRUCTIONS}\n\nCustomer ticket:\n${ticket}`,
    model: 'gpt-4.1-mini',
    tools: [lookupOrder, runDiagnostic],
  });
}

async function main(): Promise<void> {
  const ticket = readFileSync(0, 'utf8');
  const agent = buildAgent(ticket);
  const result = await run(agent, 'Triage the ticket in your instructions.');
  console.log(result.finalOutput);
}

main();
