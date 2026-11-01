import { execFileSync } from 'node:child_process';

const STATUS: Record<string, string> = { api: 'ok', db: 'ok' };

export function healthCheck(target: string): string {
  // Baseline: static lookup only.
  return STATUS[target] ?? 'unknown target';
}

export function restartService(name: string): void {
  // Admin-only helper used by admin.ts; NOT bound to any agent (negative control).
  execFileSync('systemctl', ['restart', name]);
}
