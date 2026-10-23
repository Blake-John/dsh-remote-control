/**
 * The password gate in front of the proxy: the login page, session cookie
 * issuance, and per-address rate limiting.
 *
 * Only this module decides whether a request may reach the Harness; the proxy
 * and the WebSocket tunnel both ask it first.
 */

import { readCookie, SESSION_COOKIE } from './state.js'

/** Path that renders and accepts the login form. */
export const LOGIN_PATH = '/__rc/login'

/** Path that ends this browser's session. */
export const LOGOUT_PATH = '/__rc/logout'

/** Attempts allowed per address per window before a cooldown. */
const ATTEMPTS_PER_WINDOW = 5

/** Length of one rate-limit window. */
const WINDOW_MS = 60_000

/** Longest cooldown after repeated failures. */
const MAX_COOLDOWN_MS = 15 * 60_000

/** Hard ceiling on tracked source addresses, so one burst cannot grow the table without limit. */
const MAX_TRACKED_ADDRESSES = 512

/** Largest accepted login body. */
const MAX_BODY_BYTES = 4096

/** Escape text for HTML text nodes and attributes. */
export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

/** Shared shell for every page the gate renders itself. */
function page({ title, heading, body }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>${escapeHtml(title)}</title>
<style>
:root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --text:#16181d; --muted:#5b6270; --line:#dfe2e8; --accent:#247bbf; --bad:#c0392b; }
@media (prefers-color-scheme: dark) { :root { --bg:#15171b; --card:#1d2026; --text:#eef0f4; --muted:#9aa2b1; --line:#2c313a; --accent:#5aa9e6; --bad:#ef6b60; } }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin:0; min-height:100svh; padding:24px 16px calc(24px + env(safe-area-inset-bottom)); background:var(--bg); color:var(--text); font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif; display:flex; align-items:flex-start; justify-content:center; }
main { width:100%; max-width:26rem; background:var(--card); border:1px solid var(--line); border-radius:16px; padding:22px; }
h1 { margin:0 0 6px; font-size:1.25rem; }
p { margin:0 0 14px; color:var(--muted); }
input[type=password], input[type=text] { width:100%; padding:14px 16px; font:400 1rem/1.4 inherit; border:1px solid var(--line); border-radius:12px; background:transparent; color:var(--text); }
label { display:block; font-size:.85rem; color:var(--muted); margin-bottom:6px; }
button { display:block; width:100%; margin-top:14px; padding:15px 16px; font:600 1rem/1 inherit; border:0; border-radius:12px; background:var(--accent); color:#fff; touch-action:manipulation; cursor:pointer; }
.error { color:var(--bad); font-weight:600; }
.hint { margin-top:16px; font-size:.85rem; color:var(--muted); }
@media (pointer:coarse) { button, input { min-height:48px; } }
</style>
</head>
<body><main><h1>${escapeHtml(heading)}</h1>${body}</main></body>
</html>`
}

/**
 * The login form.
 * @param {{label: string, title: string, message?: string, action?: string, note?: string}} options - copy.
 * @returns the page markup.
 */
export function renderLoginPage({ label, title, message, action = LOGIN_PATH, note }) {
  return page({
    title,
    heading: title,
    body: `<form method="post" action="${escapeHtml(action)}" autocomplete="off">
<label for="secret">${escapeHtml(label)}</label>
<input id="secret" name="secret" type="password" autocomplete="current-password" spellcheck="false" maxlength="200" required autofocus>
<button type="submit">${escapeHtml(label)}</button>
</form>
${message === undefined ? '' : `<p class="error" role="alert">${escapeHtml(message)}</p>`}
${note === undefined ? '' : `<p class="hint">${escapeHtml(note)}</p>`}`,
  })
}

/**
 * A plain message page (errors the gate owns, e.g. upstream unavailable).
 * @param {{title: string, heading: string, message: string, detail?: string}} options - copy.
 * @returns the page markup.
 */
export function renderMessagePage({ title, heading, message, detail }) {
  return page({
    title,
    heading,
    body: `<p>${escapeHtml(message)}</p>${detail === undefined ? '' : `<p class="hint">${escapeHtml(detail)}</p>`}`,
  })
}

/** Read one small request body as text. */
async function readBody(request, limitBytes = MAX_BODY_BYTES) {
  const chunks = []
  let total = 0
  for await (const chunk of request) {
    total += chunk.length
    if (total > limitBytes) throw new Error('request body too large')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/** Write one response and end it. */
export function respond(response, status, headers, body) {
  response.writeHead(status, { 'cache-control': 'no-store', ...headers })
  response.end(body)
}

/**
 * Only allow a same-site relative redirect target. `//host` and `/\host` are
 * protocol-relative spellings a browser would follow off-site, and control
 * characters can smuggle a header or a second path.
 * @param {unknown} value - the requested `next` parameter.
 * @returns a path that stays on this authority.
 */
export function safeNext(value) {
  if (typeof value !== 'string' || value === '') return '/'
  if (!value.startsWith('/') || value.startsWith('//')) return '/'
  if (value.includes('\\') || /[\u0000-\u001f\u007f]/u.test(value)) return '/'
  return value
}

/**
 * Session credentials and login for the entry listener.
 */
export class Gate {
  /**
   * @param {{ state: InstanceType<typeof import('./state.js').State>, logger: { info: Function, warn: Function, error: Function }, sessionDays: number, copy: {label: string, title: string, note?: string}, inviteLength: number }} options - dependencies and copy.
   */
  constructor({ state, logger, sessionDays, copy, inviteLength }) {
    this.state = state
    this.logger = logger
    this.sessionDays = sessionDays
    this.copy = copy
    this.inviteLength = inviteLength
    /** @type {Map<string, {windowStart: number, attempts: number, failures: number, blockedUntil: number}>} */
    this.attempts = new Map()
    /** @type {Map<string, Set<import('node:net').Socket>>} */
    this.sockets = new Map()
  }

  /**
   * Register a live socket so revoking its session can close it. A keep-alive
   * socket serves many requests, so repeated registration is ignored.
   * @param {string} sessionId - owning session.
   * @param {import('node:net').Socket} socket - the live socket.
   */
  track(sessionId, socket) {
    const existing = this.sockets.get(sessionId)
    if (existing !== undefined && existing.has(socket)) return
    const set = existing ?? new Set()
    set.add(socket)
    this.sockets.set(sessionId, set)
    socket.once('close', () => {
      set.delete(socket)
      if (set.size === 0) this.sockets.delete(sessionId)
    })
  }

  /** Close every socket belonging to one session. */
  closeSessionSockets(sessionId) {
    const set = this.sockets.get(sessionId)
    if (set === undefined) return 0
    let closed = 0
    for (const socket of set) {
      closed += 1
      socket.destroy()
    }
    this.sockets.delete(sessionId)
    return closed
  }

  /** Close every tracked socket (listener shutdown). */
  closeAllSockets() {
    let closed = 0
    for (const id of [...this.sockets.keys()]) closed += this.closeSessionSockets(id)
    return closed
  }

  /**
   * Resolve the request's session.
   * @param {{headers: Record<string, string | string[] | undefined>}} request - incoming request.
   * @returns {{session: object, cookie: string} | undefined}
   */
  authenticate(request) {
    const cookie = readCookie(header(request, 'cookie'), SESSION_COOKIE)
    if (cookie === undefined) return undefined
    const session = this.state.verifySession(cookie)
    if (session === undefined) return undefined
    this.state.touch(session.id)
    return { session, cookie }
  }

  /**
   * Drop address records that no longer matter, so a long-lived entry does not
   * accumulate one entry per source address forever.
   */
  pruneAttempts() {
    const now = Date.now()
    for (const [address, record] of this.attempts) {
      const idle = now - Math.max(record.windowStart, record.blockedUntil)
      if (idle > MAX_COOLDOWN_MS * 2) this.attempts.delete(address)
    }
  }

  /** Remaining cooldown for one address, in milliseconds. */
  cooldown(address) {
    const record = this.attempts.get(address)
    if (record === undefined) return 0
    const now = Date.now()
    return record.blockedUntil > now ? record.blockedUntil - now : 0
  }

  /** Record one attempt and return the cooldown it triggers. */
  recordAttempt(address, failed) {
    const now = Date.now()
    const record = this.attempts.get(address)
    if (record === undefined || now - record.windowStart >= WINDOW_MS) {
      if (this.attempts.size >= MAX_TRACKED_ADDRESSES) {
        this.pruneAttempts()
        // Still full: evict the oldest entries (the map keeps insertion order).
        while (this.attempts.size >= MAX_TRACKED_ADDRESSES) {
          const oldest = this.attempts.keys().next()
          if (oldest.done === true) break
          this.attempts.delete(oldest.value)
        }
      }
      this.attempts.set(address, { windowStart: now, attempts: 1, failures: failed ? 1 : 0, blockedUntil: 0 })
      return 0
    }
    record.attempts += 1
    if (failed) record.failures += 1
    if (record.failures >= ATTEMPTS_PER_WINDOW) {
      const over = record.failures - ATTEMPTS_PER_WINDOW
      const cooldown = Math.min(MAX_COOLDOWN_MS, WINDOW_MS * 2 ** over)
      record.blockedUntil = now + cooldown
      record.windowStart = now
      record.failures = 0
      return cooldown
    }
    return 0
  }

  /** The Set-Cookie value for one session. */
  cookieHeader(cookieValue) {
    return `${SESSION_COOKIE}=${cookieValue}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${this.sessionDays * 86_400}`
  }

  /**
   * Serve the login form or accept it.
   * @param {import('node:http').IncomingMessage} request - incoming request.
   * @param {import('node:http').ServerResponse} response - response to own.
   * @returns whether this handler owned the response.
   */
  async handle(request, response) {
    const requested = new URL(String(request.url ?? '/'), 'http://entry.invalid')
    const path = requested.pathname
    const method = String(request.method ?? 'GET').toUpperCase()
    const address = request.socket?.remoteAddress ?? 'unknown'

    if (path === LOGOUT_PATH) {
      const authenticated = this.authenticate(request)
      if (authenticated !== undefined) {
        this.state.revokeSession(authenticated.session.id)
        this.closeSessionSockets(authenticated.session.id)
        this.logger.info(`dsh-remote-control: session ${authenticated.session.label} signed out from ${address}`)
      }
      respond(response, 302, {
        location: LOGIN_PATH,
        'set-cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
      }, '')
      return true
    }

    if (path !== LOGIN_PATH) return false

    const remaining = this.cooldown(address)
    if (remaining > 0) {
      respond(response, 429, { 'content-type': 'text/html; charset=utf-8' }, renderLoginPage({
        ...this.copy,
        message: `Too many attempts. Try again in ${Math.ceil(remaining / 1000)}s.`,
      }))
      return true
    }

    if (method === 'GET' || method === 'HEAD') {
      respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, renderLoginPage(this.copy))
      return true
    }

    if (method !== 'POST') {
      respond(response, 405, { allow: 'GET, HEAD, POST' }, '')
      return true
    }

    // A cross-site form post cannot log anyone in, but rejecting it keeps the
    // gate's one mutation endpoint same-origin only.
    const origin = header(request, 'origin')
    if (origin !== undefined) {
      const host = header(request, 'host')
      if (host !== undefined && new URL(origin).host !== host) {
        respond(response, 403, { 'content-type': 'text/html; charset=utf-8' }, renderMessagePage({
          title: this.copy.title,
          heading: this.copy.title,
          message: 'Cross-site sign-in is not allowed.',
        }))
        return true
      }
    }

    let body
    try {
      body = new URLSearchParams(await readBody(request))
    } catch {
      respond(response, 400, { 'content-type': 'text/html; charset=utf-8' }, renderLoginPage({
        ...this.copy,
        message: 'That request was not readable.',
      }))
      return true
    }

    const secret = (body.get('secret') ?? '').trim()
    const next = safeNext(body.get('next') ?? requested.searchParams.get('next') ?? '')
    const facts = {
      userAgent: header(request, 'user-agent') ?? '',
      address,
    }

    let issued
    if (secret !== '' && await this.state.verifyPassword(secret)) {
      issued = this.state.createSession(facts)
      this.recordAttempt(address, false)
      this.logger.info(`dsh-remote-control: password sign-in from ${address} (${issued.session.label})`)
    } else if (secret !== '' && secret.replace(/[^A-Za-z0-9]/gu, '').length === this.inviteLength) {
      issued = this.state.redeemInvite(secret, facts)
      if (issued !== undefined) {
        this.logger.info(`dsh-remote-control: invite sign-in from ${address} (${issued.session.label})`)
      } else {
        this.recordAttempt(address, true)
        this.logger.warn(`dsh-remote-control: rejected invite from ${address}`)
      }
    } else {
      this.recordAttempt(address, true)
      this.logger.warn(`dsh-remote-control: rejected password from ${address}`)
    }

    if (issued === undefined) {
      const cooldown = this.cooldown(address)
      respond(response, cooldown > 0 ? 429 : 401, { 'content-type': 'text/html; charset=utf-8' }, renderLoginPage({
        ...this.copy,
        message: cooldown > 0
          ? `Too many attempts. Try again in ${Math.ceil(cooldown / 1000)}s.`
          : 'That password or invite code did not work.',
      }))
      return true
    }

    respond(response, 302, {
      location: next,
      'set-cookie': this.cookieHeader(issued.cookie),
    }, '')
    return true
  }
}

/** Read one header as a single string. */
export function header(request, name) {
  const value = request.headers?.[name]
  if (Array.isArray(value)) return value[0]
  return typeof value === 'string' ? value : undefined
}
