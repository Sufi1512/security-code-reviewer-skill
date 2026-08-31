# API Security Deep Scan (OWASP API Top 10)

Read this when the target exposes an HTTP API, GraphQL schema, or WebSocket endpoints.

## Route inventory — do this first

Do not grep for missing auth decorators. Grep finds routes; it cannot tell a
guarded route from an unguarded one, because the guard is usually on the
handler signature rather than the decorator line.

**Write a short throwaway script** that parses every route definition together
with its handler signature and emits one row per route: method, path, line, and
the auth dependency it carries (or `NONE`). Then read the rows where the guard
is missing or weaker than the path implies.

This produces the single most valuable structural fact in an API review —
whether authorization is complete — and it produces it as evidence rather than
as an impression. A clean result is worth reporting too: "62/62 admin routes
guarded" tells the reader you checked, rather than that you found nothing.

Framework guard patterns to match against:

| Framework | Authenticated | Privileged |
| :--- | :--- | :--- |
| FastAPI | `Depends(get_current_user)` | `Depends(get_current_admin)`, `dependencies=[...]` on the router |
| Express | `authenticate` / `requireAuth` middleware | `requireRole('admin')` |
| Django | `@login_required`, `IsAuthenticated` | `IsAdminUser`, custom permission class |
| Spring | `@PreAuthorize("isAuthenticated()")` | `@PreAuthorize("hasRole('ADMIN')")`, `@Secured` |

## Broken Function-Level Authorization (BFLA)

Cross-reference the inventory: any route under `/admin/`, `/manage/`, `/internal/`
that carries only the *authenticated* guard and not the *privileged* one is a
privilege-escalation gap. This is the highest-value check in the list — an
authenticated low-privilege user is a far more likely attacker than an anonymous one.

## Broken Object-Level Authorization (BOLA / IDOR)

For every route taking an id, a session key, or a thread id from the client:
does the handler verify that the resource **belongs to** the caller, or does it
just look the resource up? A parameter passed straight into a store lookup with
no ownership check is an IDOR.

Pay attention to identifiers that do not look like database ids — session ids,
conversation thread ids, upload tokens, and cache keys are routinely trusted
without checks because they read as opaque rather than enumerable.

Also flag any such parameter with a **shared default value** (`"default-session"`,
`"guest"`, `0`): every client that omits the parameter lands in one shared record.

## JWT configuration

- `algorithms=['none']` or `algorithm: 'none'` — **Critical**, allows unsigned tokens.
- `HS256` with a secret under 32 chars, or a secret with an `or "..."` / `getenv(..., "default")` fallback — a fail-open signing key is Critical even when the correct value is set today, because a missing env var produces a silently forgeable token rather than a startup error.
- `exp` set on encode; `verify_exp` not disabled on decode.
- Revocation state held in a process-local dict does not survive a restart and does not apply across workers. Note the real lifetime of a "revoked" token.
- Refresh token rotation: old refresh tokens invalidated on use.

## Mass assignment / over-posting

- **Python**: `Model(**request.json())`, `Model(**data)`, `update(**kwargs)` without a field allow-list.
- **Node**: `Object.assign(model, req.body)`, `model.update(req.body)`.
- **Fix**: explicit field mapping, strict Pydantic models, DTOs.

## Server-Side Request Forgery (SSRF)

Search for `requests.get/post`, `httpx`, `fetch(`, `urlopen(`, `http.get(` where
the URL derives from input. Validate against an allow-list; block `127.0.0.1`,
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (cloud metadata),
and resolve the hostname before checking — a public name can resolve to a private address.

Two things that raise severity, both easy to miss:
- The error handler returns `str(e)` to the caller, turning the endpoint into a readable oracle.
- The caller's own auth token is forwarded to the attacker-named host.

An admin-only SSRF is still worth reporting: it converts one compromised admin
session into read access across the internal network.

## Response data leakage

Responses that return whole ORM objects (`return user.dict()`, `res.json(user)`)
leak password hashes, internal ids, tokens, and unnecessary PII/PHI. Fix with
response schemas that whitelist fields explicitly.

Check the *write* path too: a field masked on read may still be stored in plaintext.

## Rate limiting and resource exhaustion

- **Is the limiter keyed on the real client?** Behind a reverse proxy, `request.client.host` is the proxy's address unless the server is started with proxy-header trust (`--proxy-headers` plus `--forwarded-allow-ips`). Without it, every request buckets to one key: per-client limiting silently does not exist, and the global budget can be exhausted by one caller to lock everyone out. Verify the server's launch flags, not just the limiter code.
- **Is the store shared?** An in-memory dict desynchronises across workers.
- **Which endpoints are actually covered?** List the call sites of the limiter and diff them against the route inventory. Expensive unauthenticated endpoints — file upload, transcription, inference, embedding proxies — are the ones that matter and are routinely the ones missed.
- **Are accumulating buffers bounded?** A streaming or WebSocket handler that appends to a buffer and only checks size after an end-of-stream marker can be driven to unbounded memory by a client that never sends the marker. Check that the size ceiling is enforced *inside* the receive loop.

## GraphQL

- Introspection disabled in production.
- Query depth and complexity limits.
- Field-level authorization, not just resolver-entry authorization.

## WebSockets

CORS does not apply to WebSocket handshakes — a wildcard CORS fix does nothing here.
Verify the handshake checks `Origin` itself, and that credentials are validated
before the socket is accepted rather than after the first message.

**Check parameter defaults on the handshake signature.** A default value on a
credential parameter means the endpoint is reachable with no credentials at all,
and any real value sitting in that default is a committed secret.
