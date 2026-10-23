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
 * @module @local/dsh-remote-control
 */

import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { listAddresses, parseCidr } from './lib/addresses.js'
import { Gate, respond } from './lib/gate.js'
import { MOBILE_BOOT_SCRIPT, MOBILE_STYLESHEET } from './lib/mobile-css.js'
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
    tunnel: new Tunnel({ facts, credential, logger, gate }),
    logger,
    copy,
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

  // The phone-facing layer is additive and switchable: every rule is scoped to
  // an attribute the client half sets, so with the switch off the document is
  // the shipped UI and with it on nothing else changes.
  ctx.on('webserver/index-inject', (table) => {
    if (!config.mobile.stylesheet) return
    table.push({ kind: 'script', placement: 'head', text: MOBILE_BOOT_SCRIPT })
    table.push({ kind: 'style', text: MOBILE_STYLESHEET })
  })

  // Tear the entry socket down with the plugin.
  ctx.effect(() => () => listener.stop(), 'dsh-remote-control: entry listener teardown')

  const described = listener.status()
  logger.info(`dsh-remote-control: ${state.listener.enabled
    ? `entry listener ${described.state} at ${described.url ?? 'an unavailable address'}`
    : 'entry listener is off; enable it under Settings → Remote Control'}`)

  return { state, listener, credential, rpc }
}
