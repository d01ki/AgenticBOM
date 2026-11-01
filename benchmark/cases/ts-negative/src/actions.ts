import { rmSync } from 'fs';

export function clean(path: string) {
  rmSync(path, { recursive: true });
}
