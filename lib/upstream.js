/**
 * Upstream facts and the credential the entry listener holds on the phone's
 * behalf.
 *
 * The Harness browser credential (the `dsh-auth-*` cookie) is obtained once by
 * redeeming the process launch token against the bound listener, then kept in
 * memory and attached to every proxied request. The phone never sees it, which
 * is what makes "revoke this device" actually revoke: the client only ever
 * holds this plugin's own session cookie.
 */

import http from 'node:http'
import https from 'node:https'

/** Reader for one HTTP response's Set-Cookie headers. */
function setCookies(headers) {
  const value = headers['set-cookie']
  if (Array.isArray(value)) return value
  return typeof value === 'string' ? [value] : []
}

/** The `name=value` part of one Set-Cookie line. */
function cookiePair(line) {
  const separator = line.indexOf(';')
  return separator === -1 ? line.trim() : line.slice(0, separator).trim()
}

/**
 * Facts about the bound Harness listener, which is also the proxy target.
 * @param {{getOrigin: () => string}} webServer - the Web carrier service.
 * @returns {{origin: string, protocol: string, hostname: string, port: number, authority: string}}
 */
export function upstreamFacts(webServer) {
  const origin = webServer.getOrigin()
  const url = new URL(origin)
  const port = Number(url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : url.port)
  return {
    origin,
    protocol: url.protocol,
    // URL keeps IPv6 brackets in `hostname`; the transport wants them off.
    hostname: url.hostname.replace(/^\[/u, '').replace(/\]$/u, ''),
    port,
    authority: url.host,
  }
}

/**
 * Issue one request to the local Harness listener.
 * @param {{protocol: string, hostname: string, port: number}} target - where to connect.
 * @param {{method?: string, path?: string, headers?: Record<string, string>, timeoutMs?: number}} options - request shape.
 * @returns {Promise<{status: number, headers: Record<string, string | string[] | undefined>, body: Buffer}>}
 */
export function requestUpstream(target, options = {}) {
  const transport = target.protocol === 'https:' ? https : http
  return new Promise((resolve, reject) => {
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: options.method ?? 'GET',
      path: options.path ?? '/',
      headers: options.headers ?? {},
      // The listener is this process's own; a self-signed certificate is the
      // only thing it can present, and the socket never leaves the machine.
      ...target.protocol === 'https:' ? { rejectUnauthorized: false, servername: undefined } : {},
    }, (response) => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks),
      }))
      response.on('error', reject)
    })
    request.setTimeout(options.timeoutMs ?? 5000, () => {
      request.destroy(new Error('upstream credential request timed out'))
    })
    request.on('error', reject)
    request.end()
  })
}

/**
 * Holds the Harness browser credential for proxied requests.
 */
export class UpstreamCredential {
  /**
   * @param {{webServer: object, connection: object}} services - resolved carrier services.
   * @param {{timeoutMs?: number}} [options] - acquisition timeout.
   */
  constructor(services, options = {}) {
    this.services = services
    this.timeoutMs = options.timeoutMs ?? 5000
    /** @type {string | undefined} */
    this.cookie = undefined
    /**
     * Origin the held cookie was minted for. The Desktop host binds an
     * OS-assigned port on every launch, so a different origin is a restarted
     * Harness whose cookie cannot be reused.
     * @type {string | undefined}
     */
    this.origin = undefined
    /** @type {'idle' | 'ready' | 'failed'} */
    this.state = 'idle'
    /** @type {string | undefined} */
    this.error = undefined
    /** @type {number | undefined} */
    this.acquiredAt = undefined
    /** @type {Promise<string> | undefined} */
    this.pending = undefined
  }

  /** What the settings page shows. */
  info() {
    return {
      state: this.state,
      error: this.error,
      acquiredAt: this.acquiredAt,
      cookie: this.cookie === undefined
        ? 'absent'
        : `present (${String(this.cookie.length)} chars)`,
    }
  }

  /** Drop the held credential so the next request re-acquires one. */
  invalidate() {
    this.cookie = undefined
    this.origin = undefined
    this.state = 'idle'
  }

  /**
   * The upstream origin right now, or undefined while the listener is unreadable.
   * @returns {string | undefined}
   */
  currentOrigin() {
    try {
      return upstreamFacts(this.services.webServer).origin
    } catch {
      return undefined
    }
  }

  /**
   * Redeem the process launch token for a browser cookie.
   * @returns the cookie pair, e.g. `dsh-auth-abc=…`.
   */
  async acquire() {
    const target = upstreamFacts(this.services.webServer)
    const tokenized = this.services.connection.authenticatedUrl(`${target.protocol}//${target.authority}/`)
    const url = new URL(tokenized)
    const response = await requestUpstream(target, {
      method: 'GET',
      path: `${url.pathname}${url.search}`,
      headers: { host: target.authority, accept: 'text/html' },
      timeoutMs: this.timeoutMs,
    })
    const pairs = setCookies(response.headers)
      .map(cookiePair)
      .filter(pair => /^dsh-auth-/u.test(pair))
    if (pairs.length === 0) {
      throw new Error(`the bound listener returned ${response.status} without a dsh-auth cookie; is browser authentication mounted?`)
    }
    // The root exchange mints exactly one browser credential; take it and keep
    // the choice deterministic instead of guessing by length.
    return pairs[0]
  }

  /**
   * Return a usable credential, acquiring it on first use.
   * @returns the cookie pair.
   */
  async ensure() {
    if (this.cookie !== undefined) {
      // Re-acquire before the hop, not after a 401: a body-carrying POST and a
      // WebSocket upgrade cannot be replayed, so a stale cookie discovered at
      // the upstream would surface as a broken request instead of a retry.
      if (this.currentOrigin() === this.origin) return this.cookie
      this.invalidate()
    }
    // Concurrent 401s must not each redeem the launch token.
    this.pending ??= this.acquire()
      .then((cookie) => {
        this.cookie = cookie
        this.origin = this.currentOrigin()
        this.state = 'ready'
        this.error = undefined
        this.acquiredAt = Date.now()
        return cookie
      })
      .catch((error) => {
        this.state = 'failed'
        this.error = error instanceof Error ? error.message : String(error)
        throw error
      })
      .finally(() => {
        this.pending = undefined
      })
    return this.pending
  }

  /**
   * Handle a proxied 401: acquire once more, then report whether a retry makes sense.
   * @param {string} [stale] - the credential that was refused; a newer one that
   * another request already obtained is kept instead of being discarded.
   * @returns whether a fresh credential is available.
   */
  async refresh(stale) {
    if (stale === undefined || this.cookie === stale) this.invalidate()
    try {
      await this.ensure()
      return true
    } catch {
      return false
    }
  }
}
