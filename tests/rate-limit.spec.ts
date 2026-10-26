import { describe, expect, it } from 'vitest'
import { DEFAULT_THROTTLE_POLICY, LoginThrottle } from '../src/rate-limit.ts'

describe('LoginThrottle', () => {
  const policy = { maxAttempts: 3, windowMs: 60_000, lockoutMs: 30_000 }

  it('allows an untouched key', () => {
    const throttle = new LoginThrottle(policy)
    expect(throttle.check(['u:alice'], 0)).toEqual({ allowed: true })
  })

  it('allows attempts below the budget and locks once it is spent', () => {
    const throttle = new LoginThrottle(policy)
    throttle.fail(['u:alice'], 0)
    throttle.fail(['u:alice'], 10)
    expect(throttle.check(['u:alice'], 20).allowed).toBe(true)
    throttle.fail(['u:alice'], 30)
    expect(throttle.check(['u:alice'], 40)).toEqual({ allowed: false, retryAfterMs: 30_000 - 10 })
  })

  it('reports the longest remaining lockout across keys', () => {
    const throttle = new LoginThrottle(policy)
    throttle.fail(['s:1.2.3.4'], 0)
    throttle.fail(['s:1.2.3.4'], 0)
    throttle.fail(['s:1.2.3.4'], 0)
    throttle.fail(['u:alice'], 10_000)
    throttle.fail(['u:alice'], 10_000)
    throttle.fail(['u:alice'], 10_000)
    const verdict = throttle.check(['s:1.2.3.4', 'u:alice'], 10_500)
    expect(verdict.allowed).toBe(false)
    if (!verdict.allowed) expect(verdict.retryAfterMs).toBe(29_500)
  })

  it('unlocks when the lockout expires', () => {
    const throttle = new LoginThrottle(policy)
    for (let i = 0; i < policy.maxAttempts; i += 1) throttle.fail(['u:alice'], 0)
    expect(throttle.check(['u:alice'], 1_000).allowed).toBe(false)
    expect(throttle.check(['u:alice'], 30_001).allowed).toBe(true)
  })

  it('expires failures that fall out of the window', () => {
    const throttle = new LoginThrottle(policy)
    throttle.fail(['u:alice'], 0)
    throttle.fail(['u:alice'], 1)
    // Two failures aged out; only the fresh one counts toward the budget.
    throttle.fail(['u:alice'], 61_000)
    expect(throttle.check(['u:alice'], 61_001).allowed).toBe(true)
  })

  it('clears a key after a successful login', () => {
    const throttle = new LoginThrottle(policy)
    for (let i = 0; i < policy.maxAttempts - 1; i += 1) throttle.fail(['u:alice'], 0)
    throttle.succeed(['u:alice'])
    throttle.fail(['u:alice'], 1)
    throttle.fail(['u:alice'], 2)
    expect(throttle.check(['u:alice'], 3).allowed).toBe(true)
  })

  it('drops stale buckets so the map cannot grow without bound', () => {
    const throttle = new LoginThrottle(policy)
    throttle.fail(['u:alice'], 0)
    throttle.fail(['u:bob'], 0)
    expect(throttle.size).toBe(2)
    throttle.sweep(120_000)
    expect(throttle.size).toBe(0)
  })

  it('keeps a locked bucket through a sweep', () => {
    const throttle = new LoginThrottle(policy)
    for (let i = 0; i < policy.maxAttempts; i += 1) throttle.fail(['u:alice'], 0)
    throttle.sweep(1_000)
    expect(throttle.size).toBe(1)
  })

  it('validates its policy at construction time', () => {
    expect(() => new LoginThrottle({ ...policy, maxAttempts: 0 })).toThrow(/maxAttempts/)
    expect(() => new LoginThrottle({ ...policy, windowMs: 0 })).toThrow(/windowMs/)
    expect(() => new LoginThrottle({ ...policy, lockoutMs: -1 })).toThrow(/lockoutMs/)
  })

  it('ships a usable default policy', () => {
    expect(DEFAULT_THROTTLE_POLICY.maxAttempts).toBeGreaterThan(0)
    expect(DEFAULT_THROTTLE_POLICY.windowMs).toBeGreaterThan(0)
    expect(DEFAULT_THROTTLE_POLICY.lockoutMs).toBeGreaterThan(0)
  })
})
