import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import type { CredentialProvider, CredentialRef } from '@deepseek-ai/dsh-credentials'

/** scrypt cost parameters. `N` must be a power of two. */
export interface ScryptParams {
  N: number
  r: number
  p: number
}

/** Cost parameters of hashes written before this field existed (Node defaults). */
export const LEGACY_SCRYPT_PARAMS: ScryptParams = { N: 16384, r: 8, p: 1 }

/** OWASP's current scrypt floor: N=2^17 (128 MiB), r=8, p=1. */
export const OWASP_SCRYPT_PARAMS: ScryptParams = { N: 2 ** 17, r: 8, p: 1 }

/** Extra headroom so `maxmem` never sits exactly at the 128·N·r requirement. */
const SCRYPT_MAXMEM_FLOOR = 256 * 1024 * 1024

export interface UserRecord {
  username: string
  hash: string
  salt: string
  /**
   * Cost parameters `hash` was derived with. Absent on records written before
   * this field existed, which always means {@link LEGACY_SCRYPT_PARAMS}; the
   * next successful login rewrites the record with the store's current policy.
   */
  kdf?: ScryptParams
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
 * Derive one password digest from a plaintext, a hex salt and cost parameters.
 * Injectable so tests can count derivations or substitute cheap parameters
 * instead of measuring wall clock.
 */
export type PasswordHasher = (password: string, saltHex: string, params: ScryptParams) => string

/** Default hasher: scrypt with explicit, recorded cost parameters. */
const scryptPassword: PasswordHasher = (password, saltHex, params) =>
  scryptSync(password, Buffer.from(saltHex, 'hex'), KEY_LEN, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: Math.max(SCRYPT_MAXMEM_FLOOR, 256 * params.N * params.r),
  }).toString('hex')

/** Whether `a` costs at least as much as `b` on every axis that matters. */
function atLeastAsStrong(a: ScryptParams, b: ScryptParams): boolean {
  return a.N >= b.N && a.r >= b.r && a.p >= b.p
}

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
    /**
     * Cost parameters for hashes this store writes. Records below it are
     * upgraded lazily on the next successful login, so raising it is safe:
     * no password reset is required and no account is locked out.
     */
    private readonly policy: ScryptParams = LEGACY_SCRYPT_PARAMS,
    private readonly hasher: PasswordHasher = scryptPassword,
  ) {
    // Fail loudly at boot instead of at the first login: scrypt itself only
    // objects when it is asked to derive, which would look like a login bug.
    const { N, r, p } = policy
    if (!Number.isInteger(N) || N < 1024 || (N & (N - 1)) !== 0) {
      throw new Error(`dsh-login: scrypt N must be a power of two >= 1024 (got ${String(N)})`)
    }
    if (!Number.isInteger(r) || r < 1) throw new Error(`dsh-login: scrypt r must be a positive integer (got ${String(r)})`)
    if (!Number.isInteger(p) || p < 1) throw new Error(`dsh-login: scrypt p must be a positive integer (got ${String(p)})`)
  }

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
      username, salt, hash: this.hasher(password, salt, this.policy), kdf: { ...this.policy },
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
    const target = record ?? { salt: DUMMY_SALT, hash: DUMMY_HASH, kdf: this.policy }
    // Derive with the parameters the stored hash was written with, so raising
    // the policy never locks an existing account out; unknown users derive at
    // the current policy, keeping a miss as expensive as a hit.
    const params = target.kdf ?? LEGACY_SCRYPT_PARAMS
    const matches = constantTimeEqualHex(this.hasher(password, target.salt, params), target.hash)
    if (record === undefined || record.disabled === true || !matches) return undefined
    // Lazy migration: a hash below the current policy is rewritten now, so the
    // cost can be raised without asking an administrator to reset passwords.
    if (!atLeastAsStrong(params, this.policy)) await this.upgradeHash(record.username, password).catch(() => {})
    return record
  }

  /**
   * Re-derive `username`'s hash at the store's current policy and persist it.
   * Best-effort: the caller has already authenticated, so a failed upgrade must
   * never fail the login. Re-reads the list so a concurrent admin edit is not
   * clobbered with a stale copy.
   */
  private async upgradeHash(username: string, password: string): Promise<void> {
    const records = await this.list()
    const current = records.find(u => u.username === username)
    if (current === undefined) return
    const salt = randomBytes(16).toString('hex')
    current.salt = salt
    current.hash = this.hasher(password, salt, this.policy)
    current.kdf = { ...this.policy }
    await this.credentials.set(this.ref, JSON.stringify(records))
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
    record.hash = this.hasher(password, record.salt, this.policy)
    record.kdf = { ...this.policy }
    await this.credentials.set(this.ref, JSON.stringify(records))
  }

  async remove(username: string): Promise<void> {
    const records = await this.list()
    const next = records.filter(u => u.username !== username)
    if (next.length === records.length) throw new Error(`unknown user "${username}"`)
    await this.credentials.set(this.ref, JSON.stringify(next))
  }
}
