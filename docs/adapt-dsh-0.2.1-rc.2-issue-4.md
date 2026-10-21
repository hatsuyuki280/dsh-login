# 0.3.6 — issue #4: the ordinary-user allow-list drifted off the wire surface

> Applies to: `@islibaodong/dsh-login` 0.3.6, DSH 0.2.1-rc.2.
> Fixes: [issue #4](https://github.com/islibaodong/dsh-login/issues/4).
> Supersedes the "the wire method registry needed no edits" claim in the 0.3.5 notes:
> the *upstream* registry did not change between 0.2.1-alpha.5 and rc.2, but dsh-login's
> copy of it had already fallen behind in 0.2.x and nothing detected that.

## Symptom

On a DSH 0.2.1-rc.2 deployment with dsh-login 0.3.5, **ordinary (non-admin) users** only:

| # | Action in the GUI | Error |
|---|---|---|
| ① | 「添加工作区」 pick a directory | `not permitted for this user` |
| ② | composer → model dialog | `forbidden: notpermittedforthisuser` |
| ③ | 设置 → 模型 | `加载提供商目录失败: not permitted for this user` |

Admins were unaffected: `api-bridge-auth.ts` short-circuits admin requests before
the method gate, so only the `USER_ALLOWED` path was exercised — which is exactly
the path that had gone stale.

## Root cause

`src/api-filter.ts` kept `USER_ALLOWED` as a hand-maintained list of
`namespace.method` strings, written against the **pre-0.2 wire spelling**. The
bridge wall gates every `POST /api/<namespace>.<method>` against that set:

```ts
// src/api-bridge-auth.ts
if (!USER_ALLOWED.has(endpoint)) { /* quiet forbidden envelope, else 403 */ }
```

On 0.2.1-rc.2 **every entry in the old list was a dead name** and **every real
name was missing**, so an ordinary user's model dialog, workspace picker and
provider catalog all died at the same gate. Nothing failed loudly: a denial looks
exactly like a permission decision, which is why this survived a release.

| Retired spelling (0.3.5) | Real name on 0.2.1-rc.2 |
|---|---|
| `session.models` | `session.modelCatalog` |
| `session.history` | `session.page` |
| `llm.providers`, `llm.models` | `llm.listProviders`, `llm.listConfigurableProviders`, `llm.discoverModels` |
| `skill.list` | `skills.list` |
| `goal.create/edit/pause/resume/complete/clear` | `goals.create/edit/pause/resume/complete/clear/get` |
| `subagent.list/history/prompt/interrupt` | `subagents.prompt`, `subagents.interruptByParent` |
| `host.describe`, `respond`, `workspace.list`, `workspaceFiles.readAll`, `workspaceFiles.readRelated` | — (no such methods) |
| — (never listed) | `directoryPicker.*`, `session.canOpenWorkspacePath`, `session.openWorkspacePath`, `session.workspacePathApplications`, `session.initializeDefaultModel`, `schedule.*`, `speech.*`, `userQuestions.*`, `messageFeedback.*`, `sessionFeedback.record`, `fileUploads.upload`, `fileReferences.list`, `permissionPresets.catalog`, `productAnalytics.*`, `cotTranslation.*`, `sessionReferenceResolver.candidates`, `commands.*`, `remoteAccess.follow` |

## What 0.3.6 changes

### 1. The allow-list is now an exhaustive classification of the real registry

`src/api-filter.ts` classifies **all 146** methods of the DSH 0.2.1-rc.2 wire
surface (`TypertRemoteMap` in `packages/*/lib/typert.remote-client.d.ts`) into
three disjoint buckets:

- `USER_ALLOWED` — **92**: per-user, session/agent-scoped features.
- `ADMIN_ONLY_METHODS` — **53**: instance-level surface, never reachable by an
  ordinary user.
- `HOST_INTERNAL_METHODS` — **1**: `workspace.initializeDefault` (first-use
  plumbing; neither a user nor an admin UI action).

`WIRE_SURFACE` is the derived union, and `classifyWireMethod()` /
`isKnownWireMethod()` / `isUserAllowed()` read from it. "Unknown" is now a
distinct answer from "known but admin-only", which is what makes drift
detectable.

### 2. Drift is a test failure, not a user-facing outage

- `scripts/dump-wire-surface.mjs` re-derives the registry from a DSH checkout
  (`node scripts/dump-wire-surface.mjs --checkout ../deepseek-harness`), writing
  `tests/fixtures/wire-surface.json` (version-stamped snapshot, 146 methods).
- `tests/wire-surface.spec.ts` (9 cases) asserts: buckets are disjoint; the union
  equals the snapshot; sizes stay 92/53/1; **no dead entries**; every method
  issue #4 reported is user-reachable; every retired spelling is absent; and —
  when a checkout is reachable — the *live* registry is cross-checked against the
  snapshot, so an upstream rename fails the suite instead of locking users out.

### 3. An unknown method says so in the host log

A denial for a method that is not on this build's wire surface is reported **once
per method** through `ctx.logger` (fallback: `console.warn`), naming the DSH
version the allow-list targets:

```
dsh-login: /api/<ns>.<method> was denied for '<user>' but is not part of the DSH
0.2.1-rc.2 wire surface this build knows — upstream may have renamed it;
refresh src/api-filter.ts (node scripts/dump-wire-surface.mjs)
```

Ordinary admin-only denials stay quiet (that is what `quietDenials` is for); this
only fires for names the build has never heard of.

### 4. The same names, everywhere

`src/capabilities.ts` derives `USER_DOMAINS` / `adminOnlyMethods()` /
`allDomains()` from the buckets (no second hand-written list), `isReadProbe()`
matches read verbs as **prefixes** (`listProviders`, `listIndexes`,
`discoverModels`, `getState` — exact-word matching had classified those as writes
and denied them loudly), and `src/remote-guard.ts`'s `ADMIN_ONLY_NAMESPACES` adds
`pluginInventory`, `pluginRegistryProbe`, `dynamicCordisRunner`, `claudeCodeMods`.

## Security review of the widened surface

The three symptoms are fixed by admitting real user-scoped methods; two of them
deserve an explicit rationale.

- **`directoryPicker.pick`/`list`/`createDirectory` (issue #4 symptom ①) —
  admitted.** The picker only *browses* host directories; the privilege boundary
  sits one call later, where `workspace.create` remains confined to the caller's
  sandbox (`workspaceRoot/<username>`), so a non-admin still cannot register a
  workspace outside it. Ordinary users can already run shell as the host user via
  `terminal.*` (admitted since 0.2.1), so host-directory browsing adds no new
  capability class — denying it bought isolation in appearance only, at the cost
  of a completely broken add-workspace flow.
- **`agentPresets.*` stays admin-only** even though the client half reads and
  selects presets: a preset carries a system prompt plus a plugin composition
  that is injected into new sessions, i.e. authoring surface for the instance.
  This was already the 0.3.5 decision and 0.3.6 does not revisit it.
- **`llm.discoverModels` is admitted** (0.3.5 forbade it): it is what settings →
  models calls to enumerate a provider's models, it is per-user, and it returns
  catalog metadata only.
- Everything instance-level — `account.*`, `credentials.*`, `settings.*`,
  `agentPresets.*`, `pluginManager.*`, `pluginMarket.*`, `pluginRegistryProbe.*`,
  `pluginInventory.*`, `dynamicCordisRunner.*` (arbitrary host-side code),
  `claudeCodeMods.*` — stays refused, and `tests/wire-surface.spec.ts` pins that.

## Re-syncing after an upstream change

```bash
# from the dsh-login checkout, with a DSH checkout nearby
node scripts/dump-wire-surface.mjs --checkout ../deepseek-harness   # refresh the snapshot
node node_modules/vitest/vitest.mjs run tests/wire-surface.spec.ts  # shows the diff
```

Then classify each new method into one of the three buckets (the suite fails
until you do), bump `WIRE_SURFACE_DSH_VERSION`, and rebuild (`npm run build`).
A method that is wrongly bucketed fails `no dead entries` only if it does not
exist; a *policy* mistake (admitting something instance-level) has to be caught in
review — the bucket sizes in the test are the tripwire for that.
