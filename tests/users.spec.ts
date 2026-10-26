import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { UserStore } from '../src/users.ts'
import { MemoryCredentials } from './memory-credentials.ts'

const ref = credentialRef('DSH_LOGIN_PASSWORD_USERS')

function makeStore(): { store: UserStore; creds: MemoryCredentials } {
  const creds = new MemoryCredentials()
  return { store: new UserStore(creds as never, ref), creds }
}

describe('UserStore disabled accounts', () => {
  it('setDisabled(true) blocks verify; setDisabled(false) restores it', async () => {
    const { store } = makeStore()
    await store.create('alice', 'pw', true)
    await store.setDisabled('alice', true)
    expect((await store.list()).find(u => u.username === 'alice')?.disabled).toBe(true)
    expect(await store.verify('alice', 'pw')).toBeUndefined()
    await store.setDisabled('alice', false)
    expect((await store.list()).find(u => u.username === 'alice')?.disabled).toBeUndefined()
    expect((await store.verify('alice', 'pw'))?.username).toBe('alice')
  })

  it('setDisabled throws for an unknown user', async () => {
    const { store } = makeStore()
    await expect(store.setDisabled('ghost', true)).rejects.toThrow(/unknown user/i)
  })
})

describe('UserStore', () => {
  it('starts empty', async () => {
    const { store } = makeStore()
    expect(await store.isEmpty()).toBe(true)
  })

  it('first user becomes admin, second not by default', async () => {
    const { store } = makeStore()
    const admin = await store.create('alice', 'pw-a-123456', true)
    expect(admin.isAdmin).toBe(true)
    const bob = await store.create('bob', 'pw-b-123456', false)
    expect(bob.isAdmin).toBe(false)
    expect((await store.list()).map(u => u.username)).toEqual(['alice', 'bob'])
  })

  it('verify accepts correct password and rejects wrong/unknown', async () => {
    const { store } = makeStore()
    await store.create('alice', 'correct horse', true)
    expect((await store.verify('alice', 'correct horse'))?.username).toBe('alice')
    expect(await store.verify('alice', 'wrong')).toBeUndefined()
    expect(await store.verify('nobody', 'x')).toBeUndefined()
  })

  it('verify is false after setPassword change', async () => {
    const { store } = makeStore()
    await store.create('alice', 'old', true)
    await store.setPassword('alice', 'new')
    expect(await store.verify('alice', 'old')).toBeUndefined()
    expect((await store.verify('alice', 'new'))?.username).toBe('alice')
  })

  it('create rejects duplicates and invalid input', async () => {
    const { store } = makeStore()
    await store.create('alice', 'pw', true)
    await expect(store.create('alice', 'pw2', false)).rejects.toThrow(/exists/i)
    await expect(store.create('Bad Name', 'pw', false)).rejects.toThrow(/username/i)
    await expect(store.create('bob', '', false)).rejects.toThrow(/password/i)
  })

  it('remove deletes the user', async () => {
    const { store } = makeStore()
    await store.create('alice', 'pw', true)
    await store.remove('alice')
    expect(await store.isEmpty()).toBe(true)
  })
})

describe('UserStore verify work equalization (no username timing oracle)', () => {
  /**
   * Store whose hasher counts derivations. Counting is a deterministic proxy
   * for the KDF cost: if a miss derives zero times while a hit derives once,
   * the wall-clock difference is exactly what an attacker measures.
   */
  function makeCountingStore(): { store: UserStore; derivations: () => number } {
    const creds = new MemoryCredentials()
    let count = 0
    const hasher = (password: string, saltHex: string): string => {
      count += 1
      return createHash('sha256').update(`${saltHex}:${password}`).digest('hex')
    }
    return { store: new UserStore(creds as never, ref, hasher), derivations: () => count }
  }

  it('derives exactly once for an unknown username', async () => {
    const { store, derivations } = makeCountingStore()
    await store.create('alice', 'pw')
    const before = derivations()
    expect(await store.verify('nobody', 'x')).toBeUndefined()
    expect(derivations() - before).toBe(1)
  })

  it('derives exactly once for a wrong password', async () => {
    const { store, derivations } = makeCountingStore()
    await store.create('alice', 'pw')
    const before = derivations()
    expect(await store.verify('alice', 'wrong')).toBeUndefined()
    expect(derivations() - before).toBe(1)
  })

  it('derives exactly once for a correct password', async () => {
    const { store, derivations } = makeCountingStore()
    await store.create('alice', 'pw')
    const before = derivations()
    expect((await store.verify('alice', 'pw'))?.username).toBe('alice')
    expect(derivations() - before).toBe(1)
  })

  it('derives exactly once for a disabled account', async () => {
    const { store, derivations } = makeCountingStore()
    await store.create('alice', 'pw')
    await store.setDisabled('alice', true)
    const before = derivations()
    expect(await store.verify('alice', 'pw')).toBeUndefined()
    expect(derivations() - before).toBe(1)
  })

  it('spends the same work on unknown, disabled and wrong-password attempts', async () => {
    const { store, derivations } = makeCountingStore()
    await store.create('alice', 'pw')
    await store.create('bob', 'pw')
    await store.setDisabled('bob', true)

    const delta = async (username: string, password: string): Promise<number> => {
      const before = derivations()
      await store.verify(username, password)
      return derivations() - before
    }

    expect(await delta('nobody', 'x')).toBe(await delta('alice', 'wrong'))
    expect(await delta('bob', 'pw')).toBe(await delta('alice', 'wrong'))
  })
})
