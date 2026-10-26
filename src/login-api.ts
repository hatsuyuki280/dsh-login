/**
 * Login/logout/setup API handlers for the multi-user flow.
 *
 * Login parses `{username, password}` and verifies against the UserStore
 * (scrypt hashes in the DSH credentials system). Setup is gated on
 * `users.isEmpty()` and creates the forced-admin first account, logging it
 * in immediately. The old single-password credential flow (announce +
 * credentials-storage helpers) was removed with the multi-user switch —
 * the old `password` config key remains configured but unused by these
 * handlers (it now only namespaces the `_USERS` credential ref).
 */
import type { ServerResponse, IncomingMessage } from 'node:http'
import type { WebRoute } from '@deepseek-ai/dsh-host-webserver'
import type { SessionStore } from './session.ts'
import type { UserStore } from './users.ts'
import type { TrustedHosts } from './hosts.ts'
import { readBody, sendJson } from './http-json.ts'
import { buildCookieHeader, buildClearCookieHeader, extractSessionToken } from './auth.ts'
import type { LoginThrottle } from './rate-limit.ts'

/** Shared dependencies for the login/setup handlers. */
export interface LoginDeps {
  users: UserStore
  store: SessionStore
  /** Session lifetime in seconds; stamped onto the Set-Cookie Max-Age. */
  sessionTtl: number
  /** TrustedHosts registry; a successful login/setup auto-learns the Host. Optional for back-compat; learning is skipped when absent. */
  hosts?: TrustedHosts
  /** Whether auto-learning a successful login's Host is enabled (config.autoTrustHosts). */
  autoTrust?: boolean
  /**
   * Failed-attempt limiter, consulted before the KDF runs. Optional so a
   * composition without it keeps working; omitting it restores the pre-#5
   * behaviour (unlimited attempts).
   */
  throttle?: LoginThrottle
}

/** Parse and validate a `{username, password}` JSON body; null on bad input. */
async function parseCredentials(req: IncomingMessage): Promise<{ username: string; password: string } | null> {
  let body: string
  try {
    body = await readBody(req)
  } catch {
    return null
  }
  let parsed: { username?: unknown; password?: unknown }
  try {
    parsed = JSON.parse(body) as { username?: unknown; password?: unknown }
  } catch {
    return null
  }
  if (typeof parsed.username !== 'string' || typeof parsed.password !== 'string') return null
  return { username: parsed.username, password: parsed.password }
}

/** Best-effort: learn the request Host into the trusted registry. */
function learnRequestHost(req: IncomingMessage, hosts: TrustedHosts): void {
  const host = req.headers.host
  if (typeof host === 'string' && host.length > 0) hosts.learn(host)
}

/**
 * The throttle keys one attempt is accounted against: the submitted username
 * (guessing one account) and the TCP peer (cycling usernames from one client).
 * The peer address is used as-is: forwarded headers are caller-controlled and
 * are never trusted here.
 */
function throttleKeys(req: IncomingMessage, username: string): string[] {
  const source = req.socket.remoteAddress ?? 'unknown'
  return [`u:${username}`, `s:${source}`]
}

/** Answer 429 with a `Retry-After` the client can honour. */
function sendTooManyAttempts(res: ServerResponse, retryAfterMs: number): void {
  res.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfterMs / 1000))))
  sendJson(res, 429, { error: 'too many attempts' })
}

/**
 * Create the POST /api/auth/login handler. Verifies `{username, password}`
 * against the UserStore and, on match, creates a session and sets the
 * cookie. 401 on invalid credentials; 500 while no user exists (setup mode).
 */
export function createLoginHandler(deps: LoginDeps): WebRoute['handler'] {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const creds = await parseCredentials(req)
    if (creds === null) {
      sendJson(res, 400, { error: 'bad request' })
      return
    }
    if (await deps.users.isEmpty()) {
      sendJson(res, 500, { error: 'no users configured' })
      return
    }
    // Reject before the KDF: a locked key must not still cost a derivation,
    // otherwise the limiter itself becomes the denial-of-service primitive.
    const keys = throttleKeys(req, creds.username)
    const verdict = deps.throttle?.check(keys)
    if (verdict !== undefined && !verdict.allowed) {
      sendTooManyAttempts(res, verdict.retryAfterMs)
      return
    }
    const record = await deps.users.verify(creds.username, creds.password)
    if (record === undefined) {
      deps.throttle?.fail(keys)
      sendJson(res, 401, { error: 'invalid credentials' })
      return
    }
    deps.throttle?.succeed(keys)
    // Best-effort audit stamp (shown in 设置-用户管理): never fail a
    // verified login over it.
    await deps.users.touchLastLogin(record.username).catch(() => {})
    const session = deps.store.create(record.username, record.isAdmin)
    if (deps.autoTrust === true && deps.hosts !== undefined) learnRequestHost(req, deps.hosts)
    res.setHeader('Set-Cookie', buildCookieHeader(session.token, deps.sessionTtl))
    sendJson(res, 200, { ok: true })
  }
}

/**
 * Create the POST /api/auth/logout handler. Revokes the session (if present)
 * and clears the cookie.
 */
export function createLogoutHandler(store: SessionStore): WebRoute['handler'] {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const token = extractSessionToken(req.headers.cookie)
    if (token !== undefined) await store.revokeDurably(token)
    res.setHeader('Set-Cookie', buildClearCookieHeader())
    res.writeHead(200)
    res.end()
  }
}

/**
 * Create the GET /logout handler: revoke the session (if present), clear
 * the cookie, and redirect to /login. A convenience twin of the POST route
 * so a plain link can log the user out.
 */
export function createLogoutRedirectHandler(store: SessionStore): WebRoute['handler'] {
  return async (req: IncomingMessage, res: ServerResponse) => {
    const token = extractSessionToken(req.headers.cookie)
    if (token !== undefined) await store.revokeDurably(token)
    res.setHeader('Set-Cookie', buildClearCookieHeader())
    res.writeHead(302, { Location: '/login' })
    res.end()
  }
}

/**
 * Create the POST /api/auth/setup handler. Only callable while no user
 * exists (first-time setup): creates the forced-admin account and logs it
 * in. Returns 403 once any user exists.
 */
export function createSetupHandler(deps: LoginDeps): WebRoute['handler'] {
  return async (req: IncomingMessage, res: ServerResponse) => {
    // First-run account creation is unauthenticated by design, so it is
    // throttled by peer before anything else (issue #5).
    const sourceKey = `s:${req.socket.remoteAddress ?? 'unknown'}`
    const verdict = deps.throttle?.check([sourceKey])
    if (verdict !== undefined && !verdict.allowed) {
      sendTooManyAttempts(res, verdict.retryAfterMs)
      return
    }
    // Security gate: only allow setup while the user store is empty.
    if (!(await deps.users.isEmpty())) {
      sendJson(res, 403, { error: 'users already exist' })
      return
    }
    const creds = await parseCredentials(req)
    if (creds === null || creds.password.length === 0) {
      // A malformed attempt still consumes the peer's budget: otherwise an
      // unauthenticated caller can hammer this route for free.
      deps.throttle?.fail([sourceKey])
      sendJson(res, 400, { error: 'bad request' })
      return
    }
    let record
    try {
      // First account is always the forced admin.
      record = await deps.users.create(creds.username, creds.password, true)
    } catch {
      deps.throttle?.fail([sourceKey])
      sendJson(res, 400, { error: 'bad request' })
      return
    }
    // First-time setup both creates the forced-admin account and signs it
    // in, so its last-login stamp starts at creation.
    await deps.users.touchLastLogin(record.username).catch(() => {})
    const session = deps.store.create(record.username, record.isAdmin)
    if (deps.autoTrust === true && deps.hosts !== undefined) learnRequestHost(req, deps.hosts)
    res.setHeader('Set-Cookie', buildCookieHeader(session.token, deps.sessionTtl))
    sendJson(res, 200, { ok: true })
  }
}
