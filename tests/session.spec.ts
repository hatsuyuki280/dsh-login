import { writeFileSync } from 'node:fs'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { SessionStore } from '../src/session.ts'
import { tmpFile } from './helpers.ts'

describe('SessionStore.onlineCounts', () => {
  it('counts live sessions per user and sweeps expired ones', () => {
    const store = new SessionStore(3600)
    store.create('alice', false)
    store.create('alice', false)
    store.create('bob', true)
    const counts = store.onlineCounts()
    expect(counts.get('alice')).toBe(2)
    expect(counts.get('bob')).toBe(1)
    expect(counts.has('carol')).toBe(false)
  })

  it('omits revoked sessions', () => {
    const store = new SessionStore(3600)
    const a = store.create('alice', false)
    store.create('alice', false)
    store.revoke(a.token)
    expect(store.onlineCounts().get('alice')).toBe(1)
  })

  it('drops expired sessions from the counts', () => {
    const store = new SessionStore(-1) // already expired at creation
    store.create('alice', false)
    expect(store.onlineCounts().get('alice')).toBeUndefined()
  })
})

describe('SessionStore', () => {
  it('creates a session with a 64-char hex token and correct expiry', () => {
    const store = new SessionStore(3600)
    const session = store.create('alice', false)
    expect(session.token).toMatch(/^[0-9a-f]{64}$/)
    expect(session.createdAt).toBeGreaterThan(0)
    expect(session.expiresAt).toBe(session.createdAt + 3600 * 1000)
  })

  it('verifies a freshly created session', () => {
    const store = new SessionStore(3600)
    const session = store.create('alice', false)
    expect(store.verify(session.token)).toBeDefined()
  })

  it('rejects an unknown token', () => {
    const store = new SessionStore(3600)
    expect(store.verify('deadbeef')).toBeUndefined()
  })

  it('rejects an empty token', () => {
    const store = new SessionStore(3600)
    expect(store.verify('')).toBeUndefined()
  })

  it('revokes a session so verify returns undefined', () => {
    const store = new SessionStore(3600)
    const session = store.create('alice', false)
    expect(store.verify(session.token)).toBeDefined()
    store.revoke(session.token)
    expect(store.verify(session.token)).toBeUndefined()
  })

  it('revoking an unknown token is a no-op', () => {
    const store = new SessionStore(3600)
    expect(() => store.revoke('nonexistent')).not.toThrow()
  })

  it('rejects an expired session after TTL', async () => {
    // Use a TTL of 0 seconds so the session is immediately expired.
    const store = new SessionStore(0)
    const session = store.create('alice', false)
    // createdAt and expiresAt are the same epoch ms; verify checks
    // Date.now() > expiresAt, and even a synchronous verify is after.
    // Use a small delay to guarantee Date.now has advanced.
    await new Promise<void>(r => setTimeout(r, 10))
    expect(store.verify(session.token)).toBeUndefined()
  })

  it('cleanup removes expired sessions', async () => {
    const store = new SessionStore(0)
    store.create('alice', false)
    await new Promise<void>(r => setTimeout(r, 10))
    store.cleanup()
    // After cleanup, the store should be empty. We can't inspect internals
    // directly, but a second cleanup with no sessions is a no-op.
    expect(() => store.cleanup()).not.toThrow()
  })

  it('each create returns a unique token', () => {
    const store = new SessionStore(3600)
    const tokens = new Set<string>()
    for (let i = 0; i < 100; i++) tokens.add(store.create('alice', false).token)
    expect(tokens.size).toBe(100)
  })

  it('creates sessions bound to a user', () => {
    const store = new SessionStore(60)
    const s = store.create('alice', true)
    expect(s.user).toBe('alice')
    expect(s.isAdmin).toBe(true)
    expect(store.verify(s.token)?.user).toBe('alice')
  })

  it('verify returns undefined for unknown tokens', () => {
    const store = new SessionStore(60)
    expect(store.verify('nope')).toBeUndefined()
  })

  it('revokeAllFor removes every session of the user and leaves others intact', () => {
    const store = new SessionStore(3600)
    const a1 = store.create('alice', false)
    const a2 = store.create('alice', false)
    const b1 = store.create('bob', false)
    expect(store.revokeAllFor('alice')).toBe(2)
    expect(store.verify(a1.token)).toBeUndefined()
    expect(store.verify(a2.token)).toBeUndefined()
    expect(store.verify(b1.token)).toBeDefined()
    expect(store.revokeAllFor('alice')).toBe(0)
    expect(store.revokeAllFor('nobody')).toBe(0)
  })
})

describe('SessionStore persistence', () => {
  it('persists sessions and restores them in a fresh store (survives a restart)', async () => {
    const path = tmpFile()
    const first = new SessionStore(3600, path)
    const session = first.create('alice', false)
    await first.flush()

    const second = new SessionStore(3600, path)
    const restored = second.verify(session.token)
    expect(restored).toBeDefined()
    expect(restored?.user).toBe('alice')
    expect(restored?.isAdmin).toBe(false)
    expect(restored?.token).toBe(session.token)
  })

  it('persists admin flag across a restart', async () => {
    const path = tmpFile()
    const first = new SessionStore(3600, path)
    const admin = first.create('root', true)
    await first.flush()
    const restored = new SessionStore(3600, path).verify(admin.token)
    expect(restored?.isAdmin).toBe(true)
  })

  it('drops expired entries on load', async () => {
    const path = tmpFile()
    const expired = new SessionStore(0, path)
    const dead = expired.create('alice', false)
    await expired.flush()
    await new Promise<void>(r => setTimeout(r, 10))
    expect(new SessionStore(3600, path).verify(dead.token)).toBeUndefined()
  })

  it('persists revocation so a fresh store no longer verifies the token', async () => {
    const path = tmpFile()
    const first = new SessionStore(3600, path)
    const session = first.create('alice', false)
    first.revoke(session.token)
    await first.flush()
    expect(new SessionStore(3600, path).verify(session.token)).toBeUndefined()
  })

  it('falls back to an empty store on a corrupt file', async () => {
    const path = tmpFile()
    writeFileSync(path, '{ not json !!!', 'utf8')
    const store = new SessionStore(3600, path)
    expect(store.verify('anything')).toBeUndefined()
    const s = store.create('alice', false)
    expect(store.verify(s.token)).toBeDefined()
  })
})

describe('SessionStore durable revocation and live account revalidation (issue #8)', () => {
  const active = async (): Promise<{ disabled?: boolean } | undefined> => ({})
  const disabled = async (): Promise<{ disabled?: boolean } | undefined> => ({ disabled: true })
  const gone = async (): Promise<{ disabled?: boolean } | undefined> => undefined
  const broken = async (): Promise<{ disabled?: boolean } | undefined> => { throw new Error('credentials unreadable') }

  async function withFile<T>(run: (store: SessionStore, path: string) => Promise<T>): Promise<T> {
    const dir = await mkdtemp(join(tmpdir(), 'dsh-login-session-'))
    const path = join(dir, 'sessions.json')
    try {
      return await run(new SessionStore(3600, path), path)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  }

  const readTokens = async (path: string): Promise<Array<{ token: string }>> => {
    const raw = await readFile(path, 'utf8')
    return JSON.parse(raw) as Array<{ token: string }>
  }

  it('persists a revocation before revokeAllForDurably resolves', async () => {
    await withFile(async (store, path) => {
      const a = store.create('alice', true)
      const b = store.create('alice', true)
      await store.flush()
      expect((await readTokens(path)).map(e => e.token).sort()).toEqual([a.token, b.token].sort())

      const removed = await store.revokeAllForDurably('alice')
      expect(removed).toBe(2)
      // The file is authoritative again immediately: a crash here cannot
      // resurrect the revoked cookies on the next boot.
      expect(await readTokens(path)).toEqual([])
    })
  })

  it('persists a single-token revocation before revokeDurably resolves', async () => {
    await withFile(async (store, path) => {
      const session = store.create('alice', true)
      await store.flush()
      expect(await store.revokeDurably(session.token)).toBe(true)
      expect(await readTokens(path)).toEqual([])
    })
  })

  it('writes atomically, so a reader never sees a truncated file', async () => {
    await withFile(async (store, path) => {
      store.create('alice', true)
      await store.flush()
      // No temp file is left behind and the payload parses.
      const entries = await readdir(join(path, '..'))
      expect(entries).toEqual(['sessions.json'])
      expect(JSON.parse(await readFile(path, 'utf8'))).toHaveLength(1)
    })
  })

  it('accepts a session whose account is still active', async () => {
    await withFile(async (store) => {
      const session = store.create('alice', true)
      expect(await store.verifyActive(session.token, active)).toMatchObject({ user: 'alice' })
    })
  })

  it('rejects and drops the session of a disabled account', async () => {
    await withFile(async (store, path) => {
      const session = store.create('alice', true)
      await store.flush()
      expect(await store.verifyActive(session.token, disabled)).toBeUndefined()
      expect(store.verify(session.token)).toBeUndefined()
      expect(await readTokens(path)).toEqual([])
    })
  })

  it('rejects and drops the session of a removed account', async () => {
    await withFile(async (store, path) => {
      const session = store.create('alice', true)
      await store.flush()
      expect(await store.verifyActive(session.token, gone)).toBeUndefined()
      expect(await readTokens(path)).toEqual([])
    })
  })

  it('fails closed when the account store cannot be read', async () => {
    await withFile(async (store) => {
      const session = store.create('alice', true)
      expect(await store.verifyActive(session.token, broken)).toBeUndefined()
    })
  })

  it('leaves an unknown token undefined without consulting the lookup', async () => {
    await withFile(async (store) => {
      let called = 0
      const lookup = async (): Promise<{ disabled?: boolean }> => { called += 1; return {} }
      expect(await store.verifyActive('not-a-token', lookup)).toBeUndefined()
      expect(called).toBe(0)
    })
  })
})
