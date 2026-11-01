import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';

const STATUS: Record<string, string> = { api: 'ok', db: 'ok' };
const ALLOWED_TARGETS = new Set(['api.internal.example', 'db.internal.example']);
const run = promisify(execFile);

export async function healthCheck(target: string): Promise<string> {
  // Fixed: allowlist guard + argv without a shell.
  if (!ALLOWED_TARGETS.has(target)) {
    return 'target not allowed';
  }
  const { stdout } = await run('curl', ['-sf', `https://${target}/healthz`]);
  return stdout || 'unhealthy';
}

export function restartService(name: string): void {
  // Admin-only helper used by admin.ts; NOT bound to any agent (negative control).
  execFileSync('systemctl', ['restart', name]);
}
