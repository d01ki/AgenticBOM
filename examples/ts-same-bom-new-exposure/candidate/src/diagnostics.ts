import { exec, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

const STATUS: Record<string, string> = { api: 'ok', db: 'ok' };
const sh = promisify(exec);

export async function healthCheck(target: string): Promise<string> {
  // Candidate: "real" health check; the tool parameter now reaches a shell command.
  const { stdout } = await sh(`curl -sf https://${target}/healthz`);
  return stdout || 'unhealthy';
}

export function restartService(name: string): void {
  // Admin-only helper used by admin.ts; NOT bound to any agent (negative control).
  execFileSync('systemctl', ['restart', name]);
}
