/**
 * Pure physical-layer permission predicates for the dsh-login gateway.
 *
 * In DSH ≥ 0.1.5-alpha.1 dsh-login no longer takes over the `/api` carrier
 * (see docs/adapt-dsh-0.1.5.md, option A): the native `connection` +
 * `api-gateway` transport owns `/api`, and dsh-login composes its login wall
 * and — via the remote/controller layer — its per-user ownership enforcement on
 * top. What remains here is the pure, package-independent predicate surface that
 * `capabilities.ts`, the `/api` bridge wall and the remote guard rely on.
 *
 * ── 0.3.6: the allow-list is now the *real* wire surface ─────────────────────
 * Until 0.3.5 this set still carried the pre-0.1.5 `RpcMethodMap` spellings
 * (`session.history`, `session.models`, `llm.providers`, `skill.list`,
 * `goal.*`, `respond`, `host.describe`, …). Upstream had long since renamed
 * every one of them, so ~20 entries were dead and the live methods they were
 * meant to describe were denied — which is exactly what issue #4 reports
 * (choosing a model, picking a workspace directory, and the settings→models
 * page all landed on a `forbidden` envelope for ordinary users).
 *
 * The lists below are transcribed from the typert wire registry of DSH
 * 0.2.1-rc.3 (`TypertRemoteMap`, one `'<namespace>/<method>'` key per endpoint,
 * 146 in total — byte-identical to 0.2.1-rc.2's registry; rc.3 touched only the
 * client UI, so the classification carries over unchanged). They are a **total,
 * disjoint classification** of that surface:
 *
 *   - {@link USER_ALLOWED}        – per-user, session/agent-scoped features.
 *   - {@link ADMIN_ONLY_METHODS}  – host configuration, credentials, plugin
 *                                   management, admin UI surfaces, host-side
 *                                   code execution.
 *   - {@link HOST_INTERNAL_METHODS} – never browser-initiated (first-use host
 *                                   plumbing); denied to ordinary users and not
 *                                   advertised to admins either.
 *
 * `USER_ALLOWED ∪ ADMIN_ONLY_METHODS ∪ HOST_INTERNAL_METHODS` must equal the
 * registry exactly. tests/wire-surface.spec.ts enforces that against the
 * vendored snapshot (tests/fixtures/wire-surface.json) and, when a harness
 * checkout is reachable, against the live registry — so an upstream rename
 * fails the build instead of silently denying a user feature.
 */

export interface AuthUser { username: string; isAdmin: boolean }

/** DSH release the snapshots in this file were transcribed from. */
export const WIRE_SURFACE_DSH_VERSION = '0.2.1-rc.3'

/**
 * The user-facing wire surface: every method an ordinary (non-admin) user may
 * call through the `/api` carrier.
 *
 * Rule of thumb: a method belongs here when it acts *within* the caller's own
 * user scope — their sessions, workspaces, goals, terminals, uploads, speech
 * preferences, scheduled runs — or reads a catalog the client needs to render
 * (llm provider/model catalogs, permission presets, skills, slash commands).
 * Anything that reconfigures the instance, exposes operator credentials, or
 * executes host-side code is in {@link ADMIN_ONLY_METHODS} instead.
 *
 * Note: the wall only gates POST (the unary RPC carrier). Stream methods
 * (`*.follow`, `terminal.attach`, `userQuestions.attachWait`, …) travel over
 * the `/api/events.mux` WebSocket, but they are listed here anyway so the
 * remote guard — which denies at the dispatch layer, streams included — stays
 * consistent with the bridge wall.
 */
export const USER_ALLOWED: ReadonlySet<string> = new Set([
  // ── session: the conversation surface ─────────────────────────────────────
  // `page` replaced the old `session.history`; `modelCatalog` replaced
  // `session.models`; `initializeDefaultModel`/`selectModel` are the model
  // picker; `canOpenWorkspacePath`/`openWorkspacePath`/
  // `workspacePathApplications` back the "open folder" flow; `control` is the
  // per-session steering stream; `projections` is the timeline projection.
  'session.attachment', 'session.cancel', 'session.canOpenWorkspacePath',
  'session.control', 'session.create', 'session.follow', 'session.fork',
  'session.initializeDefaultModel', 'session.list', 'session.modelCatalog',
  'session.openWorkspacePath', 'session.page', 'session.projections',
  'session.prompt', 'session.rename', 'session.search', 'session.selectModel',
  'session.updateQueue', 'session.workspacePathApplications',
  // ── workspace: the sidebar tree (read + the user's own mutations) ─────────
  // `follow` is the tree snapshot stream (the old `workspace.list`); every
  // mutation carries ids the guard ownership-checks.
  'workspace.archiveSession', 'workspace.create', 'workspace.delete',
  'workspace.follow', 'workspace.insertBefore', 'workspace.insertSessionBefore',
  'workspace.pinSession', 'workspace.rename', 'workspace.unarchiveSession',
  'workspace.unpinSession',
  // ── goals: per-session goal tracking (renamed from `goal.*`) ──────────────
  'goals.clear', 'goals.complete', 'goals.create', 'goals.edit', 'goals.get',
  'goals.pause', 'goals.resume',
  // ── subagents: the caller's own agent subtree ─────────────────────────────
  'subagents.interruptByParent', 'subagents.prompt',
  // ── llm: the provider/model catalogs the picker renders ───────────────────
  // (`llm.providers`/`llm.models` never existed on this wire line; these are
  // the real names — discovery is what settings→models failed on in issue #4.)
  'llm.discoverModels', 'llm.listConfigurableProviders', 'llm.listProviders',
  // ── skills: the slash-command skill list (`skills.list`) ──────────────────
  'skills.list',
  // ── job: the background job controller ────────────────────────────────────
  'job.follow', 'job.kill', 'job.list',
  // ── terminal: the sidebar terminal ────────────────────────────────────────
  // Every method is session-agent-scoped by the Gateway (the `agent` argument
  // is supplied server-side, never by the browser), so it stays inside the
  // caller's own agent subtree — the same trust boundary as `session.prompt`
  // (an agent can already run shell for the user). `list`/`retain` address a
  // session explicitly and are ownership-checked. NOTE: since 0.1.6-alpha.2
  // user terminals run with the execution environment's system-user
  // permissions (no Agent sandbox); a stricter deployment subtracts these
  // (docs/adapt-dsh-0.1.6-alpha.2.md §4).
  'terminal.attach', 'terminal.close', 'terminal.create', 'terminal.environment',
  'terminal.list', 'terminal.rename', 'terminal.retain', 'terminal.shells',
  // ── remoteAccess: the client's own grant snapshot stream ──────────────────
  // The gateway always allows it and it answers with only the caller's own
  // grants, so admitting it keeps the mount silent on every page load.
  'remoteAccess.follow',
  // ── document preview: read-only Files surface + Office→PDF ────────────────
  // Each call carries the scoped session identity (workspaceFileScopeId),
  // resolved and ownership-checked by the Gateway. No write method is exposed.
  'workspaceFiles.changes', 'workspaceFiles.list', 'workspaceFiles.read',
  'workspaceFiles.readBytes', 'workspaceFiles.stat',
  'officeToPdf.generation', 'officeToPdf.render',
  // ── speech: per-user dictation preferences + transcription ────────────────
  // `configure` persists the caller's own recognizer settings.
  'speech.cancelPreparation', 'speech.catalog', 'speech.configure',
  'speech.follow', 'speech.prepare', 'speech.transcribe',
  // ── schedule: the user's own scheduled runs ───────────────────────────────
  'schedule.catalog', 'schedule.delete', 'schedule.history', 'schedule.list',
  'schedule.update',
  // ── composer + pickers the GUI calls on ordinary-user pages ───────────────
  // `directoryPicker.*` is the "add workspace" directory chooser
  // (`ui-workspace/src/client/navigation.ts`), i.e. issue #4 symptom 1. It is
  // admitted because the capability class is already open to ordinary users
  // (`terminal.*` runs shell as the same system user).
  //
  // NOTE: `workspace.create` is NOT sandbox-confined. The 0.3.0 option-A
  // rewrite removed the ApiProxy that used to own a workspace mutation guard,
  // and the harness's own `workspaceController.create()` registers whatever
  // path the caller sends. An ordinary user can therefore register any
  // directory the service user can reach — the same class of access that
  // `terminal.*` already gives them, but not a separate guard.
  'commands.execute', 'commands.list',
  'directoryPicker.createDirectory', 'directoryPicker.list', 'directoryPicker.pick',
  // ── attachments, references, feedback, telemetry ──────────────────────────
  'fileReferences.list', 'fileUploads.upload',
  'messageFeedback.delete', 'messageFeedback.list', 'messageFeedback.put',
  'sessionFeedback.record',
  'sessionReferenceResolver.candidates',
  'permissionPresets.catalog',
  'productAnalytics.enabled', 'productAnalytics.report', 'productAnalytics.watchPolicy',
  // ── chain-of-thought translation (a per-user reading aid) ─────────────────
  'cotTranslation.limits', 'cotTranslation.translate',
  // ── the agent's ask-the-user dialog ───────────────────────────────────────
  'userQuestions.answer', 'userQuestions.attachWait',
])

/**
 * Instance-level wire surface: never reachable by an ordinary user.
 *
 * Grouped by why:
 *  - `account`              – the process-wide upstream DeepSeek Platform grant
 *                             (sign-in/out, balance, profile): operator data.
 *  - `credentials`          – secret storage describe/set/unset.
 *  - `settings`             – host configuration documents.
 *  - `agentPresets`         – preset definitions (system prompts + plugin
 *                             composition) get injected into new sessions; they
 *                             are authoring surface, kept admin-only even
 *                             though the client half reads/selects them.
 *  - `pluginManager` / `pluginMarket` / `pluginInventory` /
 *    `pluginRegistryProbe`  – install/enable/remove bundles, rewrite the
 *                             instance-wide market index list, enumerate the
 *                             host's plugin tree.
 *  - `dynamicCordisRunner`  – runs arbitrary host-side plugin code.
 */
export const ADMIN_ONLY_METHODS: ReadonlySet<string> = new Set([
  'account.ackBonusNotified', 'account.cancelSignIn', 'account.getBalance',
  'account.getProfile', 'account.getState', 'account.getUnnotifiedBonuses',
  'account.hasRunningAccountTasks', 'account.signOut', 'account.startSignIn',
  'account.watch', 'account.watchExpiry',
  'agentPresets.list', 'agentPresets.read', 'agentPresets.select',
  'claudeCodeMods.pressBand', 'claudeCodeMods.watchBand',
  'credentials.describe', 'credentials.set', 'credentials.unset',
  'dynamicCordisRunner.getClientCode', 'dynamicCordisRunner.inventory',
  'dynamicCordisRunner.invoke', 'dynamicCordisRunner.reportClientGuardFailure',
  'dynamicCordisRunner.reportRenderFailure',
  'dynamicCordisRunner.resolveInspectQuery',
  'dynamicCordisRunner.resolveRequestRun', 'dynamicCordisRunner.runHostHalf',
  'dynamicCordisRunner.settleUserRun', 'dynamicCordisRunner.stopFromPanel',
  'dynamicCordisRunner.syncInspectManifest', 'dynamicCordisRunner.undefineFromPanel',
  'pluginInventory.list',
  'pluginManager.cancelInstall', 'pluginManager.inspect',
  'pluginManager.installBundle', 'pluginManager.listBundles',
  'pluginManager.listPlugins', 'pluginManager.listVersionExemptions',
  'pluginManager.registries', 'pluginManager.removeBundle',
  'pluginManager.setBundleEnabled', 'pluginManager.setPluginEnabled',
  'pluginManager.setVersionExemption', 'pluginManager.waitForInstall',
  'pluginMarket.listIndexes', 'pluginMarket.search', 'pluginMarket.setIndexes',
  'pluginRegistryProbe.fastest',
  'settings.describe', 'settings.mutate', 'settings.openSettingsDocument',
  'settings.replace', 'settings.update',
])

/**
 * Host-internal methods: neither a user action nor an admin UI action. They
 * exist for first-use host plumbing (`workspace.initializeDefault` derives both
 * the directory name and title server-side), so they are denied to ordinary
 * users and deliberately not advertised anywhere.
 */
export const HOST_INTERNAL_METHODS: ReadonlySet<string> = new Set([
  'workspace.initializeDefault',
])

/**
 * The complete wire surface these buckets classify. Kept as a derived union so
 * the three sets above have one build-time invariant to satisfy and callers
 * have one place to ask "is this a method upstream actually ships?".
 */
export const WIRE_SURFACE: ReadonlySet<string> = new Set([
  ...USER_ALLOWED,
  ...ADMIN_ONLY_METHODS,
  ...HOST_INTERNAL_METHODS,
])

/** How a wire method is classified for an ordinary user. */
export type WireMethodClass = 'user' | 'admin' | 'host-internal' | 'unknown'

/** Classify one wire method against the buckets in this module. */
export function classifyWireMethod(method: string): WireMethodClass {
  if (USER_ALLOWED.has(method)) return 'user'
  if (ADMIN_ONLY_METHODS.has(method)) return 'admin'
  if (HOST_INTERNAL_METHODS.has(method)) return 'host-internal'
  return 'unknown'
}

/**
 * Whether the method is part of the wire surface this build knows about. An
 * `unknown` answer for a real `/api` call usually means upstream renamed a
 * method the allow-list still spells the old way — the exact failure mode issue
 * #4 hit — so the bridge wall reports those for diagnosis.
 */
export function isKnownWireMethod(method: string): boolean {
  return WIRE_SURFACE.has(method)
}

/** May an ordinary (non-admin) user call this wire method? */
export function isUserAllowed(method: string): boolean {
  return USER_ALLOWED.has(method)
}
