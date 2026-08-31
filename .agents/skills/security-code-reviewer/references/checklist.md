# Security Review Checklist

Use as a **final sweep** after Phase 4, to catch categories the targeted scan
missed. Skip sections that do not apply to the target.

Items here are prompts to investigate, not findings. Anything that fails still
goes through Phase 4 verification before it reaches the report.

## 1. Authentication & Authorization
- [ ] **Password hashing**: `bcrypt`, `Argon2`, `scrypt`, or `pbkdf2_sha256`. Never MD5/SHA1, never unsalted.
- [ ] **Session management**: cryptographically random IDs, regenerated on privilege change.
- [ ] **Authorization at every endpoint**: verified against the route inventory, not assumed.
- [ ] **Password policy**: minimum length that reflects current guidance (12+), no truncation.
- [ ] **Brute-force protection**: per-account and per-IP attempt limits on login, with backoff.
- [ ] **MFA** for privileged accounts.
- [ ] **Bootstrap admin accounts**: seeded from env at startup? Is there a rotation path, or is that password permanent?

## 2. Input Validation & Injection
- [ ] **SQL/NoSQL**: bound parameters only.
- [ ] **XSS**: context-aware output encoding (HTML, JS, URL, attribute).
- [ ] **Command injection**: no shell interpolation of user input.
- [ ] **Path traversal**: user-supplied filenames normalized and confined to a base directory.
- [ ] **File uploads**: extension allow-list, MIME validation, size cap, stored outside the webroot, never executed.
- [ ] **Deserialization**: no `pickle`, `ObjectInputStream`, or `yaml.load` on untrusted input.
- [ ] **Size limits**: request bodies, uploads, and accumulating buffers all bounded.

## 3. Cryptography & Secrets
- [ ] **Transport**: HTTPS enforced, HSTS set.
- [ ] **At rest**: sensitive data encrypted. Note that `base64` and `.encode('utf-8')` are encodings, not encryption — check what the code actually does, not what the comment claims.
- [ ] **Keys**: never hardcoded, never in defaults, rotatable.
- [ ] **Algorithms**: no MD5, SHA1, DES, RC4, ECB. Use AES-256-GCM, RSA-2048+.
- [ ] **Randomness**: `secrets` / `crypto.randomBytes`, never `random` / `Math.random` for tokens.

## 4. Session & Cookie Security
- [ ] **Flags**: `Secure`, `HttpOnly`, `SameSite`.
- [ ] **Expiration**: short TTL for sensitive sessions.
- [ ] **Revocation actually works**: survives restart, applies across all workers.
- [ ] **Unbounded session stores**: per-user dicts that only grow are a slow memory leak.

## 5. Error Handling & Logging
- [ ] **No stack traces or internal exception text** returned to clients — `str(e)` in an HTTP response leaks internal hostnames and paths.
- [ ] **No secrets, PII, or PHI in logs**, including in error paths.
- [ ] **Audit trail**: auth failures, data access, privilege and config changes.
- [ ] **Failures are logged**: a bare `except: pass` hides attacks as well as bugs.

## 6. API Security
Covered in depth by `api-security.md`. Quick sweep:
- [ ] Rate limiting present, correctly keyed, and covering the expensive endpoints.
- [ ] BOLA/IDOR: resource ownership verified, not just resource existence.
- [ ] BFLA: admin routes check role, not just authentication.
- [ ] CORS not wildcard in production.
- [ ] JWT: no `none`, strong secret with no fallback, `exp` set and verified.
- [ ] Mass assignment prevented by explicit field allow-lists.
- [ ] SSRF: user-controlled URLs validated, private ranges blocked.
- [ ] Responses filtered through explicit schemas.

## 7. Supply Chain & IaC
- [ ] **Lockfiles** committed.
- [ ] **Base images**: non-root user, minimal OS, pinned tag (not `latest`).
- [ ] **CVE scanning** automated in CI with a defined remediation window.
- [ ] **Dependency conflicts**: `pip check` clean. (A packaging concern, not a security finding — do not report it as a vulnerability.)
- [ ] **Container runtime**: not `privileged`, no `network_mode: host`, capabilities dropped.
- [ ] **Ports**: application ports not published to the host where a proxy is the intended entry point.

## 8. Environment & Secrets Management
- [ ] **`.env` gitignored at every level** and confirmed untracked via git.
- [ ] **`.env` excluded from build context** (`.dockerignore`) so it is never baked into an image layer.
- [ ] **`.env.example` holds placeholders only.**
- [ ] **Config fails loudly** when a required secret is missing — no silent insecure default.
- [ ] **Variables the code reads but the environment does not set**: the default is what is running.
- [ ] **Rotation process exists** for compromised keys.
