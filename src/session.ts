import { randomBytes } from 'node:crypto'
import { mkdir, rename, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** One created login session: token, owning user, and expiry timestamps. */
export interface Session {
  token: string
  user: string
  isAdmin: boolean
  createdAt: number
  expiresAt: number
}

/**
 * Resolve the live account record for a username, or undefined when the account
 * no longer exists. Throwing is treated as "deny" by {@link SessionStore.verifyActive}.
 */
export type UserLookup = (username: string) => Promise<{ disabled?: boolean } | undefined>

/** Debounce window for coalescing disk writes (ms), mirroring the sidecar files. */
const SAVE_DEBOUNCE_MS = 200

/**
 * Session token store with automatic TTL expiry.
 *
 * In-memory map is authoritative for the running process. When a `filePath` is
 * supplied (production — `<dataDir>/sessions.json`), sessions are persisted on
 * every mutation with a debounced, best-effort write, and restored on boot, so
 * a process restart (or a plugin reload while testing) does not silently
 * invalidate every existing login cookie — which previously turned an already-
 * loaded SPA's next `/api` call into a 401 while the page itself redirected to
 * /login only on a full reload. Tokens are written with `0o600`; the file is
 * fail-closed on boot (unreadable/corrupt → start empty).
 */
export class SessionStore {
  private readonly store = new Map<string, Session>()
  private saveTimer: ReturnType<typeof setTimeout> | undefined
  private saving: Promise<void> = Promise.resolve()
  private lastWriteOk = true

  constructor(
    private readonly ttlSeconds: number,
    private readonly filePath?: string,
  ) {
    if (filePath !== undefined) this.load()
  }

  /** Generate a 32-byte random token for `user` with its admin flag. */
  create(user: string, isAdmin: boolean): Session {
    const token = randomBytes(32).toString('hex')
    const createdAt = Date.now()
    const session: Session = { token, user, isAdmin, createdAt, expiresAt: createdAt + this.ttlSeconds * 1000 }
    this.store.set(token, session)
    this.scheduleSave()
    return session
  }

  /** Return the live session for a token, or undefined. */
  verify(token: string): Session | undefined {
    if (token.length === 0) return undefined
    const session = this.store.get(token)
    if (session === undefined) return undefined
    if (Date.now() > session.expiresAt) {
      this.store.delete(token)
      this.scheduleSave()
      return undefined
    }
    return session
  }

  /** Remove a session. Revoking an unknown token is a no-op. */
  revoke(token: string): void {
    if (this.store.delete(token)) this.scheduleSave()
  }

  /**
   * Revoke every live session belonging to `user` (user removal or password
   * change). Returns the number of sessions removed.
   */
  revokeAllFor(user: string): number {
    let removed = 0
    for (const [token, session] of this.store) {
      if (session.user === user) {
        this.store.delete(token)
        removed++
      }
    }
    if (removed > 0) this.scheduleSave()
    return removed
  }

  /**
   * Count live (unexpired) sessions per username. Used by the admin user
   * list to report online status; expired entries are swept along the way.
   */
  onlineCounts(): Map<string, number> {
    const counts = new Map<string, number>()
    const now = Date.now()
    let swept = false
    for (const [token, session] of this.store) {
      if (now > session.expiresAt) {
        this.store.delete(token)
        swept = true
        continue
      }
      counts.set(session.user, (counts.get(session.user) ?? 0) + 1)
    }
    if (swept) this.scheduleSave()
    return counts
  }

  /** Remove all expired sessions. */
  cleanup(): void {
    const now = Date.now()
    let swept = false
    for (const [token, session] of this.store) {
      if (now > session.expiresAt) {
        this.store.delete(token)
        swept = true
      }
    }
    if (swept) this.scheduleSave()
  }

  /**
   * Revoke one token and wait until the removal is durable.
   * @returns whether the write landed (false = memory-only revocation).
   */
  async revokeDurably(token: string): Promise<boolean> {
    if (this.store.delete(token)) {
      this.scheduleSave()
      return await this.writeNow()
    }
    return true
  }

  /**
   * Revoke every session of `user` and wait until the removal is durable.
   * Admin-side disable/remove/password-reset use this so a crash inside the
   * debounce window cannot resurrect a revoked cookie on the next boot.
   * @returns how many sessions were removed.
   */
  async revokeAllForDurably(user: string): Promise<number> {
    const removed = this.revokeAllFor(user)
    if (removed > 0) await this.writeNow()
    return removed
  }

  /**
   * `verify()` plus a live account check.
   *
   * A session records the identity and role captured at login (`{user,
   * isAdmin}`) and nothing re-checked the account afterwards, so disabling,
   * removing, or demoting a user left their cookie working until it expired.
   * This revalidates against the account store on the enforcement paths.
   *
   * Fail-closed: if the lookup throws, the request is refused rather than
   * riding out the failure. A dropped session is also removed from disk.
   *
   * @param token - cookie token.
   * @param lookup - resolves the live account record, or undefined when gone.
   */
  async verifyActive(
    token: string,
    lookup: (username: string) => Promise<{ disabled?: boolean } | undefined>,
  ): Promise<Session | undefined> {
    const session = this.verify(token)
    if (session === undefined) return undefined
    let record: { disabled?: boolean } | undefined
    try {
      record = await lookup(session.user)
    } catch {
      return undefined
    }
    if (record === undefined || record.disabled === true) {
      this.revoke(session.token)
      await this.writeNow()
      return undefined
    }
    return session
  }

  /** Force the pending save; resolves when the queued write settled (teardown). */
  async flush(): Promise<void> {
    if (this.saveTimer !== undefined) {
      clearTimeout(this.saveTimer)
      this.saveTimer = undefined
    }
    await this.saving
    await this.writeNow()
  }

  private load(): void {
    try {
      const raw = readFileSync(this.filePath!, 'utf8')
      const parsed = JSON.parse(raw) as unknown
      const list = Array.isArray(parsed) ? parsed : []
      const now = Date.now()
      for (const entry of list) {
        if (typeof entry !== 'object' || entry === null) continue
        const s = entry as Partial<Session>
        if (typeof s.token !== 'string' || typeof s.user !== 'string' || typeof s.isAdmin !== 'boolean') continue
        if (typeof s.createdAt !== 'number' || typeof s.expiresAt !== 'number') continue
        if (now > s.expiresAt) continue // already expired: drop on load
        this.store.set(s.token, { token: s.token, user: s.user, isAdmin: s.isAdmin, createdAt: s.createdAt, expiresAt: s.expiresAt })
      }
    } catch { /* absent or corrupt: start empty (fail-closed) */ }
  }

  private scheduleSave(): void {
    if (this.filePath === undefined || this.saveTimer !== undefined) return
    this.saveTimer = setTimeout(() => {
      this.saveTimer = undefined
      this.saving = this.writeNow()
    }, SAVE_DEBOUNCE_MS)
  }

  /**
   * Persist the live map with a temp-file + rename, so a crash mid-write can
   * never leave a truncated `sessions.json` (which load() would read as
   * "no sessions" and log everybody out). Writes are chained so two concurrent
   * saves cannot interleave and drop a revocation.
   *
   * Returns whether the write landed: a caller that promised durable
   * revocation (admin mutations) must be able to tell.
   */
  private writeNow(): Promise<boolean> {
    const path = this.filePath
    if (path === undefined) return Promise.resolve(true)
    const snapshot = `${JSON.stringify([...this.store.values()])}\n`
    this.saving = this.saving.then(async () => {
      const temp = `${path}.tmp`
      try {
        await mkdir(dirname(path), { recursive: true })
        await writeFile(temp, snapshot, { encoding: 'utf8', mode: 0o600 })
        await rename(temp, path)
        this.lastWriteOk = true
      } catch {
        this.lastWriteOk = false
      }
    })
    return this.saving.then(() => this.lastWriteOk)
  }
}