/**
 * Login attempt throttle (issue #5).
 *
 * `/api/auth/login` and `/api/auth/setup` had no counter, delay, lockout or
 * concurrency cap. Because the KDF was synchronous, an unauthenticated client
 * could both guess passwords without limit and stall the event loop that also
 * serves the GUI and agent sessions.
 *
 * This module is the in-process limiter that sits in front of the KDF. It is
 * deliberately small and dependency-free: a sliding window of recent failures
 * per key, escalating to a fixed lockout once the window is full.
 *
 * Keys are namespaced by the caller:
 *   - `u:<username>` — slows guessing against one account.
 *   - `s:<source>`   — stops a single client from cycling usernames.
 *
 * The source key is the TCP peer address. Behind a reverse proxy or tunnel
 * every request shares the proxy's address, so per-username accounting is the
 * primary control there; a deployment that terminates TLS upstream should add
 * its own limiter at the edge, and this module never trusts forwarded headers
 * (they are caller-controlled).
 */

/** Failure budget and lockout duration. */
export interface ThrottlePolicy {
  /** Failures allowed inside `windowMs` before a lockout starts. */
  maxAttempts: number
  /** Sliding window the failures are counted over. */
  windowMs: number
  /** How long a tripped key stays locked. */
  lockoutMs: number
}

/** Ten failures in five minutes buys a five minute lockout. */
export const DEFAULT_THROTTLE_POLICY: ThrottlePolicy = {
  maxAttempts: 10,
  windowMs: 5 * 60_000,
  lockoutMs: 5 * 60_000,
}

/** Verdict for one attempt. */
export type ThrottleVerdict =
  | { allowed: true }
  | { allowed: false; retryAfterMs: number }

interface Bucket {
  /** Timestamps of recent failures, oldest first. */
  hits: number[]
  /** Epoch ms until which the key is locked; 0 when not locked. */
  lockedUntil: number
}

/** How many `check()` calls between opportunistic sweeps. */
const SWEEP_EVERY = 256

/**
 * In-process sliding-window throttle. One instance per process is enough: the
 * session store and the credential store are process-local too.
 */
export class LoginThrottle {
  private readonly buckets = new Map<string, Bucket>()
  private checks = 0

  constructor(private readonly policy: ThrottlePolicy = DEFAULT_THROTTLE_POLICY) {
    if (!Number.isInteger(policy.maxAttempts) || policy.maxAttempts < 1) {
      throw new Error(`dsh-login: throttle maxAttempts must be a positive integer (got ${String(policy.maxAttempts)})`)
    }
    if (!Number.isInteger(policy.windowMs) || policy.windowMs < 1) {
      throw new Error(`dsh-login: throttle windowMs must be a positive integer (got ${String(policy.windowMs)})`)
    }
    if (!Number.isInteger(policy.lockoutMs) || policy.lockoutMs < 0) {
      throw new Error(`dsh-login: throttle lockoutMs must be >= 0 (got ${String(policy.lockoutMs)})`)
    }
  }

  /** Live key count (diagnostics/tests). */
  get size(): number {
    return this.buckets.size
  }

  /**
   * Whether the attempt may proceed.
   * @param keys - namespaced keys that must all be clear.
   * @param now - injectable clock for tests.
   */
  check(keys: readonly string[], now: number = Date.now()): ThrottleVerdict {
    this.maybeSweep(now)
    let retryAfterMs = 0
    for (const key of keys) {
      const bucket = this.buckets.get(key)
      if (bucket === undefined) continue
      if (bucket.lockedUntil > now) retryAfterMs = Math.max(retryAfterMs, bucket.lockedUntil - now)
    }
    return retryAfterMs > 0 ? { allowed: false, retryAfterMs } : { allowed: true }
  }

  /** Record one failed attempt; trips a lockout when the window fills. */
  fail(keys: readonly string[], now: number = Date.now()): void {
    for (const key of keys) {
      const bucket = this.buckets.get(key) ?? { hits: [], lockedUntil: 0 }
      bucket.hits = bucket.hits.filter(at => now - at < this.policy.windowMs)
      bucket.hits.push(now)
      if (bucket.hits.length >= this.policy.maxAttempts) {
        bucket.lockedUntil = now + this.policy.lockoutMs
        bucket.hits = []
      }
      this.buckets.set(key, bucket)
    }
  }

  /** Clear a key's history (a successful login proves the password). */
  succeed(keys: readonly string[]): void {
    for (const key of keys) this.buckets.delete(key)
  }

  /**
   * Drop buckets that hold neither a live lock nor a window-recent failure, so
   * a long-running process cannot grow this map without bound.
   */
  sweep(now: number = Date.now()): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.lockedUntil > now) continue
      const newest = bucket.hits[bucket.hits.length - 1]
      if (newest === undefined || now - newest >= this.policy.windowMs) this.buckets.delete(key)
    }
  }

  private maybeSweep(now: number): void {
    this.checks += 1
    if (this.checks % SWEEP_EVERY === 0) this.sweep(now)
  }
}
