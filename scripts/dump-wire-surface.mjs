#!/usr/bin/env node
/**
 * Regenerate tests/fixtures/wire-surface.json — the vendored snapshot of the
 * DSH typert wire registry that src/api-filter.ts classifies.
 *
 * The snapshot exists so the classification test can run without a DSH
 * checkout (CI, a plain `npm test` on a consumer machine). Refresh it every
 * time the pinned DSH line moves:
 *
 *   node scripts/dump-wire-surface.mjs                 # uses DSH_HARNESS_CHECKOUT
 *   node scripts/dump-wire-surface.mjs --checkout D:\dsh --version 0.2.2-rc.1
 *
 * The checkout is the @deepseek-ai/dsh monorepo: every API controller publishes
 * a `lib/typert.remote-client.d.ts` whose `TypertRemoteMap` carries one
 * `'<namespace>/<method>'` key per wire endpoint. Anything absent from this
 * snapshot cannot be served (the bridge wall denies it), so a stale snapshot is
 * a silent user-visible regression — that is what the classification test and
 * the live-checkout cross-check in tests/wire-surface.spec.ts guard against.
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const fixturePath = join(repoRoot, 'tests', 'fixtures', 'wire-surface.json')
const DTS_NAME = 'typert.remote-client.d.ts'
const KEY_RE = /'([A-Za-z0-9_]+)\/([A-Za-z0-9_]+)':/g

function parseArgs(argv) {
  const args = { checkout: process.env.DSH_HARNESS_CHECKOUT ?? '', version: '' }
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--checkout') args.checkout = argv[++i] ?? ''
    else if (argv[i] === '--version') args.version = argv[++i] ?? ''
  }
  return args
}

function findDtsFiles(root, out = []) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue
    const full = join(root, entry.name)
    if (entry.isDirectory()) findDtsFiles(full, out)
    else if (entry.isFile() && entry.name === DTS_NAME) out.push(full)
  }
  return out
}

/** Every wire method published by the checkout's `packages/` tree, deduped + sorted. */
export function enumerateWireSurface(checkout) {
  const packagesDir = join(checkout, 'packages')
  if (!statSync(packagesDir, { throwIfNoEntry: false })?.isDirectory()) {
    throw new Error(`not a DSH checkout (no packages/ directory): ${checkout}`)
  }
  const methods = new Set()
  for (const file of findDtsFiles(packagesDir)) {
    const source = readFileSync(file, 'utf8')
    for (const match of source.matchAll(KEY_RE)) methods.add(`${match[1]}.${match[2]}`)
  }
  return [...methods].sort()
}

function checkoutVersion(checkout) {
  try {
    const pkg = JSON.parse(readFileSync(join(checkout, 'packages', 'package.json'), 'utf8'))
    return typeof pkg.version === 'string' ? pkg.version : ''
  } catch {
    try {
      return JSON.parse(readFileSync(join(checkout, 'package.json'), 'utf8')).version ?? ''
    } catch {
      return ''
    }
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.checkout === '') {
    console.error('error: no checkout — pass --checkout <path> or set DSH_HARNESS_CHECKOUT')
    process.exit(1)
  }
  const methods = enumerateWireSurface(args.checkout)
  const dshVersion = args.version !== '' ? args.version : checkoutVersion(args.checkout)
  const fixture = {
    dshVersion,
    source: 'TypertRemoteMap keys across packages/**/lib/typert.remote-client.d.ts in the @deepseek-ai/dsh monorepo',
    count: methods.length,
    methods,
  }
  writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8')
  console.log(`wrote ${methods.length} methods (DSH ${dshVersion || 'unknown'}) → ${fixturePath}`)
}

// Only run when invoked directly — tests import enumerateWireSurface().
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main()
