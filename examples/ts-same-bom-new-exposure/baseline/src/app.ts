// Support triage agent (synthetic demo fixture).
import { Agent, run } from '@openai/agents';
import { readFileSync } from 'node:fs';
import { lookupOrder, runDiagnostic } from './tools';

const BASE_INSTRUCTIONS =
  'You are a support triage agent. Use lookup_order for order questions and run_diagnostic only for documented health checks.';

export function buildAgent(): Agent {
  return new Agent({
    name: 'support-triage',
    instructions: BASE_INSTRUCTIONS,
    model: 'gpt-4.1-mini',
    tools: [lookupOrder, runDiagnostic],
  });
}

async function main(): Promise<void> {
  const ticket = readFileSync(0, 'utf8');
  const agent = buildAgent();
  // The untrusted ticket stays in the user-role message.
  const result = await run(agent, ticket);
  console.log(result.finalOutput);
}

main();
