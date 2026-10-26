import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import type { CredentialProvider, CredentialRef } from '@deepseek-ai/dsh-credentials'

export interface UserRecord {
  username: string
  hash: string
  salt: string
  isAdmin: boolean
  createdAt: number
  /** Epoch ms of the user's most recent successful login; absent = never. */
  lastLoginAt?: number
  /** Disabled accounts cannot log in; absent on legacy records (= false). */
  disabled?: boolean
}

const USERNAME_PATTERN = /^[a-zA-Z0-9_-]{1,32}$/
const KEY_LEN = 64

/**
 * Derive one password digest from a plaintext and a hex salt.
 * Injectable so tests can count derivations instead of measuring wall clock.
 */
export type PasswordHasher = (password: string, saltHex: string) => string

/** Default hasher: scrypt at Node's default cost parameters. */
const scryptPassword: PasswordHasher = (password, saltHex) =>
  scryptSync(password, Buffer.from(saltHex, 'hex'), KEY_LEN).toString('hex')

/**
 * Fixed salt/digest pair used when the username does not exist (OWASP's
 * "fake verification" recipe). It is a digest of a random-looking constant
 * that no account can ever own, and it is never written to the store. Being
 * constant keeps every `verify` call at exactly one derivation: precomputing
 * a fresh dummy per process would make the *first* miss cost two.
 */
const DUMMY_SALT = 'd544771d41caa4038da830b95a70c425'
const DUMMY_HASH = 'b044ecd33a17c8ea0c3720816582b1ea7c462ce3bcf214b6a48dd889a99b2d78d4d6479903506e1a233637acc4bfc3258fc553410f06a394603cb101a9764f40'

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
}

export class UserStore {
  constructor(
    private readonly credentials: CredentialProvider,
    private readonly ref: CredentialRef,
    private readonly hasher: PasswordHasher = scryptPassword,
  ) {}

  async list(): Promise<UserRecord[]> {
    const resolved = await this.credentials.resolve(this.ref)
    if (resolved === undefined) return []
    try {
      const parsed = JSON.parse(resolved.value) as UserRecord[]
      return Array.isArray(parsed) ? parsed : []
    } catch {
      return []
    }
  }

  async isEmpty(): Promise<boolean> {
    return (await this.list()).length === 0
  }

  async create(username: string, password: string, isAdmin: boolean): Promise<UserRecord> {
    if (!USERNAME_PATTERN.test(username)) throw new Error('invalid username')
    if (password.length === 0) throw new Error('password must not be empty')
    const records = await this.list()
    if (records.some(u => u.username === username)) throw new Error(`user "${username}" already exists`)
    const salt = randomBytes(16).toString('hex')
    const record: UserRecord = {
      username, salt, hash: this.hasher(password, salt),
      isAdmin: records.length === 0 ? true : isAdmin,
      createdAt: Date.now(),
    }
    await this.credentials.set(this.ref, JSON.stringify([...records, record]))
    return record
  }

  async verify(username: string, password: string): Promise<UserRecord | undefined> {
    const record = (await this.list()).find(u => u.username === username)
    // Always derive exactly once, against the dummy target when the account
    // does not exist. Otherwise a miss returns in ~1ms while a hit spends the
    // whole KDF (~30ms), and the response time becomes an account oracle:
    // a single unauthenticated request then tells an attacker the username is
    // real. Unknown and disabled accounts therefore cost the same as a valid
    // one, and only the 401 body remains — which is already identical.
    const target = record ?? { salt: DUMMY_SALT, hash: DUMMY_HASH }
    const matches = constantTimeEqualHex(this.hasher(password, target.salt), target.hash)
    if (record === undefined || record.disabled === true) return undefined
    return matches ? record : undefined
  }

  /**
   * Set or clear the disabled flag for `username`. The caller (admin API)
   * owns the last-enabled-admin guard and session revocation.
   */
  async setDisabled(username: string, disabled: boolean): Promise<void> {
    const records = await this.list()
    const record = records.find(u => u.username === username)
    if (record === undefined) throw new Error(`unknown user "${username}"`)
    if (disabled) record.disabled = true
    else delete record.disabled
    await this.credentials.set(this.ref, JSON.stringify(records))
  }

  /**
   * Stamp `lastLoginAt` for a verified login. Best-effort audit field:
   * unknown users are a silent no-op so this can never fail a login.
   */
  async touchLastLogin(username: string): Promise<void> {
    const records = await this.list()
    const record = records.find(u => u.username === username)
    if (record === undefined) return
    record.lastLoginAt = Date.now()
    await this.credentials.set(this.ref, JSON.stringify(records))
  }

  async setPassword(username: string, password: string): Promise<void> {
    if (password.length === 0) throw new Error('password must not be empty')
    const records = await this.list()
    const record = records.find(u => u.username === username)
    if (record === undefined) throw new Error(`unknown user "${username}"`)
    record.salt = randomBytes(16).toString('hex')
    record.hash = this.hasher(password, record.salt)
    await this.credentials.set(this.ref, JSON.stringify(records))
  }

  async remove(username: string): Promise<void> {
    const records = await this.list()
    const next = records.filter(u => u.username !== username)
    if (next.length === records.length) throw new Error(`unknown user "${username}"`)
    await this.credentials.set(this.ref, JSON.stringify(next))
  }
}
