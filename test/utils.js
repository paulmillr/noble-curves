import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { dirname, join as joinPath } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export function jsonGZ(path) {
  const unz = gunzipSync(readFileSync(joinPath(__dirname, path)));
  return JSON.parse(unz.toString('utf8'));
}
