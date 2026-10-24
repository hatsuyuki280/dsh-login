# Adapting dsh-login to DSH 0.2.1-rc.3 (→ released as 0.3.7)

> Follow-up to [`docs/adapt-dsh-0.2.1-rc.2-issue-4.md`](adapt-dsh-0.2.1-rc.2-issue-4.md) (0.3.6). Watch cycle 2026-10-24 (scheduled `0 12 * * *` Asia/Shanghai); released as **0.3.7** (git tag `v0.3.7`).

## 1. Version detection

| source | value at detection (2026-10-24 12:00 +08) |
|---|---|
| npm `@deepseek-ai/dsh` dist-tags | `{latest: 0.2.1-rc.2, next: 0.2.1-rc.3, alpha: 0.2.1-alpha.5}`, `time.modified` 2026-10-23T07:54Z — the `next` tag moved rc.2 → rc.3 |
| git tag | `dsh-v0.2.1-rc.3` → `1f81c047fc` (2026-10-23 11:29:36 +0800, PR #6999 merge) |
| previous tag | `dsh-v0.2.1-rc.2` → `687f282e86` (2026-10-17 15:22:43 +0800, PR #6408) |
| commits between | **6** (`dsh-v0.2.1-rc.2..dsh-v0.2.1-rc.3 --count`) |
| npm publish state | all ten `@deepseek-ai/dsh-*` devDep packages published at `0.2.1-rc.3` (each verified via `npm view`); note `dsh-web-frontend`'s `latest` dist-tag still points at the stale `0.0.1-rc.5` — use `next` |

The six commits: release bump `d02ea370ee`; `c48f8523f2` feat(llm) follow the official `/models` listing on the DeepSeek API-key route (#6944); `39d2903841` fix(ui) nav pins / menu icons (#6883); `675164957a` feat(analytics) nav/preset tracking (#6600); `5ff29190ed` feat(ui) navigation entry customization (#6247); plus the merge itself.

## 2. Compatibility surface (what changed upstream and what it touches)

Diff rc.2..rc.3: 640 files, overwhelmingly tests/snapshots/`package.json` bumps. The dsh-login integration surface is **source-unchanged**:

| integration point | upstream change rc.2 → rc.3 | impact on dsh-login |
|---|---|---|
| `packages/host/webserver/src`, `packages/client/connection/src`, `packages/settings/settings/src`, `packages/host/frontend-static/src`, `packages/boot/app-boot` | none (package.json/test only) | gateway/fallback/index-render composition, `/api` transport + browser auth, `ctx.settings` seam, `serveStatic`, boot admission — all unchanged |
| `packages/client/modules/src` (`index.ts`) | **zero diff** | **boot-graph lever intact** — `__DSH_BOOT__` + `release` field untouched → `uiRoleGate` unaffected |
| `packages/client/runtime`, `packages/client/ui-slots` | none | still no per-identity activation gate; `uiRoleGate` remains the answer |
| `/api` wire method registry (`packages/api/*` controllers + `cordis-client-runner` api-catalog) | api-catalog changes are doc strings + a new **client** type `AnalyticsPreset = 'creator'\|'ptc'\|'minimal'\|'standard'`; **no new wire method or namespace** | verified mechanically: `node scripts/dump-wire-surface.mjs --checkout E:\code\deepseek-harness --version 0.2.1-rc.3` → 146 methods, the ordered method list **byte-identical** to the committed rc.2 snapshot (Compare-Object diff count 0). `USER_ALLOWED` / `ADMIN_ONLY_METHODS` / `HOST_INTERNAL_METHODS` need no edits |
| changed TS source | NEW package `ui-entry-customization` (#6247); `ui-sidebar/panel-pins.ts`, `ui-sidebar-right/guide-pins.ts`, `ui-conversation/view-pins.ts` (+2-line `slots.ts`); `ui-primitives` Menu/Tooltip; `ui-workspace/navigation.ts` blank-reuse logic; llm catalog re-home (`llm-deepseek-account` → `llm-deepseek` `listed-catalog.ts`/`listing-cache.ts`, #6944); product-analytics events (#6600) | all client-UI/internal — no wire surface, no new admin-only community bundle → `ADMIN_ONLY_UI_PLUGINS` unchanged; native UI rides the ungated path as always |
| vendored pins | unchanged: cordis `4.0.5`, schemastery `3.18.5`, include `1.0.10`, loader `1.0.6` (one transitive tool bumped 3.1.8 → 3.1.9 in the lockfile) | no vendor retarget needed |

## 3. Changes shipped (0.3.7)

- **`package.json`** — `version` → `0.3.7`; the 10 `@deepseek-ai/dsh-*` devDependencies retargeted `^0.2.1-rc.2` → `^0.2.1-rc.3`. **The plugin's own peerDependencies are unchanged**: the `>=0.2.1-alpha.1 <0.3.0-0` branches already admit rc.3 (same-tuple prerelease).
- **`src/api-filter.ts`** — metadata only: `WIRE_SURFACE_DSH_VERSION = '0.2.1-rc.3'` and the header note that the classification is transcribed from rc.3's registry, byte-identical to rc.2's. **No method-list changes.**
- **`tests/fixtures/wire-surface.json`** — regenerated at rc.3 (`dshVersion` → `0.2.1-rc.3`; method list unchanged).
- **No other source changes.** `src/remote-guard.ts`, `src/capabilities.ts`, `src/ui-gate.ts`, `src/web-runtime.ts`, `src/api-bridge-auth.ts` and the gateway are untouched. (The `remote-guard.ts:81` historical comment still says "DSH 0.2.1-rc.2 (dsh-login 0.3.6, issue #4)" — it documents *when those namespaces were first listed*, which stays true.)
- **`dist/*`** — rebuilt (`npm run build`): `dist/client.js` byte-identical to the committed file (client half unchanged); `dist/index.js`/`.map` re-stamp `WIRE_SURFACE_DSH_VERSION`.
- **Docs** — this file; README / README.zh banner + status + adaptation history + tracking/evaluation updates; `.claude/rules/changelog.md` + `gotchas.md` entries.

## 4. Verification

| step | result |
|---|---|
| `npm install` (after devDep retarget) | changed 22 packages; node_modules confirmed `0.2.1-rc.3` × 10 with cordis 4.0.5 / schemastery 3.18.5 / include 1.0.10 / loader 1.0.6; no ERESOLVE |
| wire surface | dump at rc.3 = 146 methods, byte-identical to the rc.2 snapshot |
| `vitest run` | **21 files / 267 tests green** — once on the rc.2 tree before the retarget, and again against the rc.3 builds after it (baseline unchanged, as with 0.3.5) |
| `npm run build` | exit 0 (`dist/client.js` 37134 chars; `dist/index.js` + map re-stamped) |
| `npm run verify:imports` | all ok |

As with every release: the per-user isolation guard composed over the native `typertGateway` ([`docs/compose-guard.md`](compose-guard.md)) and the two-browser isolation sign-off remain **deployment-side acceptance steps** (see [`docs/verify-option-A.md`](verify-option-A.md) §B).

## 5. Multi-user / role verdict

- **No native multi-user accounts at rc.3.** The recurring `multi.?user|multiuser|role.?based|\brbac\b` grep still yields exactly the one standing hit: `packages/api/remote-access/README.md` — the authorize-only non-owner-Peer substrate from alpha.3, unchanged. No user/account/auth package exists upstream; dsh-login remains the account/authn layer.
- **Whole-UI role gating is still not natively implementable.** `packages/client/runtime` and `packages/client/ui-slots` carry no `role`/`permission`/`isAdmin` concept; the client still activates every bundle unconditionally. rc.3's navigation-entry customization is content-level configuration — a different axis from a permission gate. dsh-login's own `uiRoleGate` (since 0.3.0) remains THE answer, and the boot-graph lever it uses is untouched at rc.3.
- The new UI packages (`ui-entry-customization`, the pin/menu tweaks, the analytics events, the llm catalog re-home) are native, non-admin client UI — they ride the ungated default path, and the `/api` allow-list (`apiBridgeAuth` + `USER_ALLOWED`) stays the security boundary. The `llm-deepseek` catalog re-home happens behind already-admitted method names (`llm.listProviders`/`llm.discoverModels`), so nothing moves in the classification.

**Conclusion: no new multi-user capability upstream; no source adaptation needed. 0.3.7 is a devDep retarget + version-pin metadata release.**
