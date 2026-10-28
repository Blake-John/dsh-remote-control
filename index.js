/**
 * dsh-remote-control — expose the Harness Web GUI to a phone on a network the
 * user already trusts, behind one permanent password.
 *
 * The plugin owns a second listener bound to one concrete address (the phone's
 * entry point) and reverse-proxies it to the loopback Harness listener. The
 * Harness keeps its own token/cookie authentication untouched; this plugin
 * holds that credential server-side, so a phone never possesses it. That is
 * what makes "revoke this device" real.
 *
 * No tunnel, no NAT traversal: reaching the entry address across networks is
 * the user's Tailscale / ZeroTier / LAN decision.
 *
 * @module dsh-remote-control
 */

import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { listAddresses, parseCidr } from './lib/addresses.js'
import { Diagnostics } from './lib/diagnostics.js'
import { Gate, respond } from './lib/gate.js'
import { EntryListener } from './lib/listener.js'
import { Proxy } from './lib/proxy.js'
import { clampInt, State } from './lib/state.js'
import { Tunnel } from './lib/tunnel.js'
import { UpstreamCredential, upstreamFacts } from './lib/upstream.js'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-control'

/**
 * Services this plugin needs, resolved by {@link resolveServices} at activation
 * instead of a declared `inject`: in a profile-composed tree a declared
 * dependency the fiber cannot resolve fails the whole entry, while the
 * non-throwing lookup keeps the plugin inert (with one warning) instead.
 */
const REQUIRED_SERVICES = ['webServer', 'connection']

/** Own RPC channel: the shared `/api` channel belongs to the Typert Gateway. */
const RPC_CHANNEL = '/remoteControl'

/** Shortest accepted permanent password. */
const MIN_PASSWORD_LENGTH = 8

/** Gate copy, chosen by config. */
const GATE_COPY = {
  zh: {
    title: '远程访问 Harness',
    label: '密码',
    note: '输入在 Harness「设置 → 远程控制」里设定的永久密码；一次性邀请码同样可用。',
  },
  en: {
    title: 'Remote Harness access',
    label: 'Password',
    note: 'Enter the permanent password set under Settings → Remote Control. A one-time invite code works too.',
  },
}

/**
 * Narrow-scope markup kept from v1: only rules that cannot change a desktop
 * layout, because every rule is behind a media query.
 */
const MOBILE_STYLESHEET = `
html { -webkit-text-size-adjust: 100%; }
@media (max-width: 700px) {
  /* iOS zooms the page when a focused field renders below 16px. */
  input, textarea, select { font-size: max(16px, 1em); }
}
@media (pointer: coarse) {
  button, [role="button"], a { touch-action: manipulation; }
}
@supports (padding: env(safe-area-inset-bottom)) {
  body { padding-bottom: env(safe-area-inset-bottom); }
}
`.trim()

/**
 * First script the page runs: park every error in a bounded buffer and flush
 * it to the plugin's collector. Kept dependency-free and failure-proof — a
 * failing reporter must never add an error of its own.
 */
const CLIENT_ERROR_CAPTURE = `
(() => {
  const queue = []
  const push = (source, message, stack) => {
    if (queue.length >= 40) queue.shift()
    queue.push({ source, message: String(message ?? ''), stack: String(stack ?? ''), at: Date.now() })
  }
  window.addEventListener('error', (event) => {
    push('error', event.message, event.error && event.error.stack)
  })
  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason
    push('rejection', reason && (reason.message || reason.code) || String(reason), reason && reason.stack)
  })
  const flush = () => {
    if (queue.length === 0) return
    const body = JSON.stringify(queue.splice(0, queue.length))
    try {
      fetch('/__rc/client-errors', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
        keepalive: true,
      }).catch(() => {})
    } catch { }
  }
  setInterval(flush, 5000)
  window.addEventListener('pagehide', flush)

  // The resource failure under probe registers no exception: the provider's
  // plugin simply never applies, and the module system's own importError sits
  // behind ctx.modules, not on the window. So the page reports what it can
  // see: whether the boot graph names the rows, and whether their bundles are
  // fetchable from this device's own network position.
  const probe = () => {
    const rows = []
    const push = (message) => {
      if (queue.length >= 40) queue.shift()
      queue.push({ source: 'probe', message: String(message).slice(0, 4000), stack: '', at: Date.now() })
    }
    try {
      const boot = globalThis.__DSH_BOOT__
      const wanted = (boot && boot.entries) || []
      const interesting = wanted.filter(row => /workspace-files|client-resources|documentpreview|api-remotes|api-gateway/.test(row.id))
      push('boot-entries total=' + wanted.length + ' matching=' + JSON.stringify(interesting.map(row => ({ id: row.id, rev: row.rev }))))
      const loader = globalThis.__ModuleLoader__
      push('loader-mode=' + (loader && loader.mode))
      // The desktop Firefox control passed, so the difference is this engine.
      // Report the newer platform APIs the client build assumes; one missing
      // member explains a plugin that loads but never applies.
      const features = {
        withResolvers: typeof Promise.withResolvers === 'function',
        allSettled: typeof Promise.allSettled === 'function',
        any: typeof Promise.any === 'function',
        randomUUID: typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function',
        subtle: typeof crypto !== 'undefined' && crypto.subtle !== undefined,
        replaceAll: typeof ''.replaceAll === 'function',
        arrayAt: typeof [].at === 'function',
        structuredClone: typeof structuredClone === 'function',
        resizeObserver: typeof ResizeObserver === 'function',
        textDecoderStream: typeof TextDecoderStream === 'function',
        compressionStream: typeof CompressionStream === 'function',
        webSocket: typeof WebSocket === 'function',
        abortController: typeof AbortController === 'function',
        requestIdleCallback: typeof requestIdleCallback === 'function',
        cssSupports: typeof CSS !== 'undefined' && typeof CSS.supports === 'function',
        visibilityState: document.visibilityState,
      }
      const missing = Object.entries(features).filter(([, v]) => v === false).map(([k]) => k)
      push('engine-features missing=' + JSON.stringify(missing) + ' full=' + JSON.stringify(features))
      const targets = interesting.filter(row => typeof row.url === 'string').slice(0, 6)
      Promise.all(targets.map(row => fetch(row.url, { method: 'GET', cache: 'no-store' })
        .then(response => row.id + ' -> ' + response.status + ' ' + (response.headers.get('content-type') ?? ''))
        .catch(error => row.id + ' -> FETCH-ERROR ' + error)))
        .then((results) => {
          for (const line of results) push(line)
          push('probe-complete')
          setTimeout(flush, 800)
        })
    } catch (probeError) {
      push('probe-failed ' + probeError)
      setTimeout(flush, 800)
    }
  }
  setTimeout(probe, 12000)
})();
`.trim()

/**
 * Normalize the row config so a malformed field degrades to a default.
 * @param {unknown} raw - the row's raw config.
 * @returns normalized config.
 */
export function normalizeConfig(raw) {
  const config = raw !== null && typeof raw === 'object' ? raw : {}
  const invite = config.invite !== null && typeof config.invite === 'object' ? config.invite : {}
  const mobile = config.mobile !== null && typeof config.mobile === 'object' ? config.mobile : {}
  return {
    statePath: typeof config.statePath === 'string' && config.statePath.trim() !== '' ? config.statePath.trim() : undefined,
    diagnosticsPath: typeof config.diagnosticsPath === 'string' && config.diagnosticsPath.trim() !== '' ? config.diagnosticsPath.trim() : undefined,
    diagnostics: config.diagnostics !== false,
    defaultPort: clampInt(config.defaultPort, 3080, 1, 65_535),
    sessionDays: clampInt(config.sessionDays, 180, 1, 3650),
    locale: config.locale === 'en' ? 'en' : 'zh',
    upstreamTimeoutMs: clampInt(config.upstreamTimeoutMs, 5000, 500, 60_000),
    invite: {
      ttlMinutes: clampInt(invite.ttlMinutes, 10, 1, 1440),
      length: clampInt(invite.length, 6, 4, 12),
      maxActive: clampInt(invite.maxActive, 5, 1, 20),
    },
    mobile: { stylesheet: mobile.stylesheet !== false },
  }
}

/**
 * Plugin entry: mount once the Web carrier and Connection exist, so a profile
 * without them keeps this plugin inert.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin context.
 * @param {unknown} rawConfig - the row's config.
 */
export function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)
  const attach = () => {
    const services = resolveServices(ctx)
    if (services === undefined) return false
    createRemoteControl({ ctx, config, ...services })
    return true
  }
  if (attach()) return
  // A sibling row may still be mounting. Retry on a low-frequency timer and say
  // so once; the entry stays off until the carrier is reachable.
  let waited = 0
  const timer = setInterval(() => {
    if (attach()) {
      clearInterval(timer)
      return
    }
    waited += 250
    if (waited >= 30_000) {
      clearInterval(timer)
      createLogger(ctx.get?.('logger')).warn(
        `dsh-remote-control: ${REQUIRED_SERVICES.join(' and ')} never became reachable; the entry stays off`,
      )
    }
  }, 250)
  ctx.effect(() => () => clearInterval(timer), 'dsh-remote-control: carrier wait')
}

/**
 * Resolve the two carrier services this plugin needs.
 *
 * A declared `inject` gives ordinary property access, but a row inserted by a
 * profile bundle can activate in a tree where that declaration has not been
 * applied to its fiber yet. `ctx.get` never throws and resolves the same
 * singletons, so both paths are tried before giving up.
 * @param {import('@deepseek-ai/cordis').Context} ctx - plugin context.
 * @returns {{webServer: object, connection: object} | undefined}
 */
export function resolveServices(ctx) {
  try {
    const webServer = ctx.webServer
    const connection = ctx.connection
    if (webServer !== undefined && connection !== undefined) return { webServer, connection }
  } catch {
    // Not injected: fall through to the non-throwing lookup.
  }
  try {
    const webServer = ctx.get?.('webServer')
    const connection = ctx.get?.('connection')
    if (webServer !== undefined && connection !== undefined) return { webServer, connection }
  } catch {
    // Absent in this tree.
  }
  return undefined
}

/**
 * Read one small request body as text.
 * @param {import('node:http').IncomingMessage} request - request stream.
 * @param {number} [limitBytes] - largest accepted body.
 * @returns {Promise<string>}
 */
async function readRequestBody(request, limitBytes = 1_048_576) {
  const chunks = []
  let total = 0
  for await (const chunk of request) {
    total += chunk.length
    if (total > limitBytes) throw new Error('request body too large')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/**
 * Adapt whatever the runtime exposes as a logger into the four methods this
 * plugin calls, so a profile without a logger plugin stays quiet instead of
 * failing activation.
 * @param {unknown} raw - `ctx.logger` or undefined.
 * @returns {{info: Function, warn: Function, error: Function, debug: Function}}
 */
function createLogger(raw) {
  const pick = (name) => (typeof raw?.[name] === 'function' ? raw[name].bind(raw) : () => {})
  return { info: pick('info'), warn: pick('warn'), error: pick('error'), debug: pick('debug') }
}

/**
 * Mount the entry listener, its gate, the proxy, and the RPC surface.
 * @param {import('@deepseek-ai/cordis').Context} ctx - injected context.
 * @param {ReturnType<typeof normalizeConfig>} config - normalized config.
 * @returns the live pieces, for tests and future tooling.
 */
export function createRemoteControl({ ctx, config, webServer, connection }) {
  const logger = createLogger(ctx.get?.('logger') ?? ctx.logger)
  // Prefer the composition's own home resolver, so the ledger lands beside the
  // rest of this profile's data even when DSH_HOME is not exported.
  const homePath = ctx.get?.('dshHomePath')
  const home = process.env.DSH_HOME
    ?? (typeof homePath === 'function' ? homePath() : undefined)
    ?? tmpdir()
  const statePath = config.statePath ?? join(home, 'remote-control', 'state.json')
  const state = new State(statePath, { sessionDays: config.sessionDays })
  // Beside the state file, so a report can be handed over without hunting for
  // a terminal that may not be attached.
  const diagnostics = new Diagnostics({
    path: config.diagnosticsPath ?? join(home, 'remote-control', 'sockets.log'),
    enabled: config.diagnostics,
  })
  const credential = new UpstreamCredential({ webServer, connection }, { timeoutMs: config.upstreamTimeoutMs })
  const copy = () => GATE_COPY[config.locale]
  const gate = new Gate({
    state,
    logger,
    sessionDays: config.sessionDays,
    copy,
    inviteLength: config.invite.length,
  })

  /** Upstream facts, or a thrown error the settings page renders. */
  const facts = () => upstreamFacts(webServer)

  const listener = new EntryListener({
    state,
    gate,
    proxy: new Proxy({ facts, credential, logger }),
    tunnel: new Tunnel({ facts, credential, logger, gate, diagnostics }),
    logger,
    copy,
    diagnostics,
  })

  // Resume the previous entry configuration, reporting a bind failure instead
  // of failing the whole plugin.
  if (state.listener.enabled) {
    void listener.apply({ ...state.listener }).then((result) => {
      if (!result.ok) logger.error(`dsh-remote-control: could not restore the entry listener: ${result.message}`)
    })
  }

  /** The status document the settings page renders. */
  const status = () => {
    let upstream
    try {
      const described = facts()
      upstream = {
        ok: true,
        origin: described.origin,
        authority: described.authority,
        protocol: described.protocol,
        credential: credential.info(),
      }
    } catch (error) {
      upstream = { ok: false, error: error instanceof Error ? error.message : String(error) }
    }
    state.pruneInvites()
    return {
      upstream,
      listener: listener.status(),
      addresses: listAddresses(state.listener.port || config.defaultPort),
      password: { set: state.hasPassword(), updatedAt: state.password?.updatedAt ?? null },
      sessions: state.listSessions(),
      invites: state.invites.map(entry => ({ expiresAt: entry.expiresAt })),
      invite: { ttlMinutes: config.invite.ttlMinutes, length: config.invite.length, maxActive: config.invite.maxActive },
      mobile: config.mobile,
      sessionDays: config.sessionDays,
      limits: { minPasswordLength: MIN_PASSWORD_LENGTH },
      statePath,
      diagnostics: diagnostics.info(),
    }
  }

  /** Validate and store an allow list. */
  const parseAllowFrom = (value) => {
    if (!Array.isArray(value) || value.length === 0) return { ok: true, value: [] }
    const entries = value.filter(item => typeof item === 'string' && item.trim() !== '').map(item => item.trim())
    for (const entry of entries) {
      if (parseCidr(entry) === undefined) {
        return { ok: false, message: `"${entry}" is not an IPv4/IPv6 address or CIDR block.` }
      }
    }
    return { ok: true, value: entries }
  }

  /** One RPC method, returning the Connection envelope. */
  const rpc = async (method, payload) => {
    const args = payload !== null && typeof payload === 'object' ? payload : {}
    const fail = (code, message) => ({ ok: false, error: { code: `remote-control/${code}`, message, details: {} } })
    try {
      switch (method) {
        case 'ping':
          return { ok: true, value: { pong: true } }

        case 'status':
          return { ok: true, value: status() }

        case 'listener/apply': {
          // An omitted field keeps its stored value: a partial call must never
          // silently widen or narrow the security configuration.
          const allow = args.allowFrom === undefined
            ? { ok: true, value: state.listener.allowFrom }
            : parseAllowFrom(args.allowFrom)
          if (!allow.ok) return fail('invalid-allow-from', allow.message)
          const result = await listener.apply({
            enabled: args.enabled === undefined ? state.listener.enabled : args.enabled === true,
            host: typeof args.host === 'string' ? args.host : state.listener.host,
            port: args.port === undefined ? state.listener.port : Number(args.port),
            allowFrom: allow.value,
          })
          if (!result.ok) return fail(result.code ?? 'bind-failed', result.message ?? 'The entry listener could not start.')
          return { ok: true, value: status() }
        }

        case 'password/set': {
          const next = typeof args.next === 'string' ? args.next : ''
          if (next.length < MIN_PASSWORD_LENGTH) {
            return fail('password-too-short', `Use at least ${MIN_PASSWORD_LENGTH} characters.`)
          }
          if (state.hasPassword()) {
            const current = typeof args.current === 'string' ? args.current : ''
            if (!(await state.verifyPassword(current))) return fail('password-mismatch', 'The current password is wrong.')
          }
          const updatedAt = await state.setPassword(next)
          // The rotated secret invalidates every session cookie at once.
          gate.closeAllSockets()
          logger.info('dsh-remote-control: permanent password updated; every session was signed out')
          return { ok: true, value: { updatedAt, signedOut: true, status: status() } }
        }

        case 'password/clear': {
          if (listener.status().state === 'listening') {
            return fail('listener-active', 'Turn the entry listener off before clearing the password.')
          }
          if (state.hasPassword() && !(await state.verifyPassword(typeof args.current === 'string' ? args.current : ''))) {
            return fail('password-mismatch', 'The current password is wrong.')
          }
          state.clearPassword()
          state.setListener({ ...state.listener, enabled: false })
          gate.closeAllSockets()
          logger.info('dsh-remote-control: password cleared; the entry was closed with it')
          return { ok: true, value: status() }
        }

        case 'sessions/revoke': {
          const session = state.revokeSession(String(args.id ?? ''))
          if (session === undefined) return fail('session-not-found', 'No such device session.')
          const closed = gate.closeSessionSockets(session.id)
          logger.info(`dsh-remote-control: revoked ${session.label}; closed ${closed} live socket(s)`)
          return { ok: true, value: status() }
        }

        case 'sessions/revoke-all': {
          const count = state.revokeAllSessions()
          const closed = gate.closeAllSockets()
          logger.info(`dsh-remote-control: revoked ${count} session(s); closed ${closed} live socket(s)`)
          return { ok: true, value: status() }
        }

        case 'sessions/rename': {
          const session = state.renameSession(String(args.id ?? ''), args.label)
          if (session === undefined) return fail('session-not-found', 'No such device session.')
          return { ok: true, value: status() }
        }

        case 'invite/create': {
          const { code, expiresAt } = state.createInvite({
            ttlMinutes: config.invite.ttlMinutes,
            length: config.invite.length,
            maxActive: config.invite.maxActive,
          })
          return { ok: true, value: { code, expiresAt, entryUrl: listener.status().url ?? null } }
        }

        case 'invite/cancel':
          state.cancelInvites()
          return { ok: true, value: status() }

        default:
          return fail('unknown-method', `Unknown remote-control method ${method}.`)
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      logger.error(`dsh-remote-control: ${method} failed: ${message}`)
      return fail('internal', message)
    }
  }

  // The channel is registered here, on the `webServer` object this plugin
  // already resolved, rather than through `connection.rpc.handle()`: that
  // helper registers its route on the *reading* context's `webServer`, which a
  // row inserted by a profile bundle cannot reach, so it throws at
  // registration. Authentication still comes from `connection.admit()`, so the
  // route answers exactly like a Connection channel.
  ctx.effect(
    () => webServer.register({
      kind: 'prefix',
      path: RPC_CHANNEL,
      handler: (request, response) => {
        void serveRpc(request, response)
      },
    }),
    'dsh-remote-control: rpc channel',
  )

  /**
   * One Connection-compatible RPC exchange: admit the request, read the
   * envelope, answer with a `server-response`.
   * @param {import('node:http').IncomingMessage} request - incoming request.
   * @param {import('node:http').ServerResponse} response - response to own.
   */
  async function serveRpc(request, response) {
    let admission
    try {
      admission = connection.admit({ headers: request.headers })
    } catch (error) {
      logger.warn(`dsh-remote-control: admission failed: ${error instanceof Error ? error.message : String(error)}`)
      respond(response, 403, { 'content-type': 'text/plain; charset=utf-8' }, 'forbidden')
      return
    }
    if (admission === undefined || 'rejection' in admission) {
      const rejection = admission?.rejection ?? 403
      respond(response, rejection, { 'content-type': 'text/plain; charset=utf-8' }, rejection === 401 ? 'unauthorized' : 'forbidden')
      return
    }

    const pathname = new URL(String(request.url ?? '/'), 'http://entry.invalid').pathname
    const endpoint = pathname.startsWith(`${RPC_CHANNEL}/`)
      ? pathname.slice(RPC_CHANNEL.length + 1)
      : undefined
    if (String(request.method ?? 'GET').toUpperCase() !== 'POST' || endpoint === undefined || endpoint === '') {
      respond(response, 404, { 'content-type': 'text/plain; charset=utf-8' }, 'not found')
      return
    }
    const mediaType = String(request.headers['content-type'] ?? '').split(';', 1)[0].trim().toLowerCase()
    if (mediaType !== 'application/json') {
      respond(response, 415, { 'content-type': 'text/plain; charset=utf-8' }, 'content type must be application/json')
      return
    }

    let body
    try {
      body = JSON.parse(await readRequestBody(request))
    } catch {
      respond(response, 400, { 'content-type': 'text/plain; charset=utf-8' }, 'body is not JSON')
      return
    }
    if (body === null || typeof body !== 'object'
      || body.type !== 'client-request' || typeof body.rpcId !== 'string' || body.method !== endpoint) {
      respond(response, 400, { 'content-type': 'text/plain; charset=utf-8' }, 'invalid client-request envelope')
      return
    }

    const result = await rpc(endpoint, body.payload)
    respond(response, 200, { 'content-type': 'application/json; charset=utf-8' },
      JSON.stringify({ type: 'server-response', rpcId: body.rpcId, result }))
  }

  // Narrow-screen polish for the shipped shell; a desktop layout is untouched.
  ctx.on('webserver/index-inject', (table) => {
    if (!config.mobile.stylesheet) return
    table.push({ kind: 'style', text: MOBILE_STYLESHEET })
  })

  // First thing the page runs: capture errors into a bounded buffer and hand
  // them to the collector on a timer. The resource failure this probes can
  // happen before any plugin console ever reaches a desktop, so the page
  // itself must keep the record.
  ctx.on('webserver/index-inject', (table) => {
    if (!config.diagnostics) return
    table.push({ kind: 'script', placement: 'head', text: CLIENT_ERROR_CAPTURE })
  })

  // Client-side errors ride a plain route next to the RPC channel: the
  // resource failure this probes can happen before the RPC half works, so the
  // collector must not depend on admission succeeding. The report is accepted
  // only from a request the gate or the Harness carrier already trusts.
  ctx.effect(
    () => webServer.register({
      kind: 'exact',
      path: '/__rc/client-errors',
      handler: (request, response) => {
        void collectClientErrors(request, response)
      },
    }),
    'dsh-remote-control: client error collector',
  )

  /**
   * Store one client error report.
   * @param {import('node:http').IncomingMessage} request - incoming report.
   * @param {import('node:http').ServerResponse} response - response to own.
   */
  async function collectClientErrors(request, response) {
    // A proxied page request carries the entry session; a direct loopback hit
    // carries the Harness cookie instead. Both name a reader we already trust.
    const trusted = gate.authenticate(request) !== undefined
      || (() => { try { return connection.admit({ headers: request.headers }) !== undefined } catch { return false } })()
    if (!trusted) {
      respond(response, 401, { 'content-type': 'text/plain; charset=utf-8' }, 'unauthorized')
      return
    }
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    const body = Buffer.concat(chunks)
    if (body.length > 8192) {
      respond(response, 413, { 'content-type': 'text/plain; charset=utf-8' }, 'too large')
      return
    }
    try {
      const reports = JSON.parse(body.toString('utf8'))
      if (!Array.isArray(reports)) throw new TypeError('expected an array')
      for (const report of reports.slice(0, 20)) {
        if (report !== null && typeof report === 'object') {
          diagnostics.record('client-error', {
            agent: request.headers['user-agent'],
            message: String(report.message ?? '').slice(0, 500),
            stack: String(report.stack ?? '').slice(0, 2000),
            source: String(report.source ?? ''),
          })
        }
      }
      respond(response, 204, {}, '')
    } catch {
      respond(response, 400, { 'content-type': 'text/plain; charset=utf-8' }, 'invalid')
    }
  }

  // Tear the entry socket down with the plugin.
  ctx.effect(() => () => listener.stop(), 'dsh-remote-control: entry listener teardown')

  const described = listener.status()
  logger.info(`dsh-remote-control: ${state.listener.enabled
    ? `entry listener ${described.state} at ${described.url ?? 'an unavailable address'}`
    : 'entry listener is off; enable it under Settings → Remote Control'}`)

  return { state, listener, credential, rpc }
}
