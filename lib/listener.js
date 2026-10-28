/**
 * The entry listener's lifecycle: bind one concrete local address, gate every
 * request through the password, proxy or tunnel what the gate admits, and
 * rebind live when the settings page changes the address.
 *
 * Two-phase rebinding keeps a failed change from costing the working entry:
 * a new address is bound first and the old one is only closed afterwards.
 */

import http from 'node:http'

import { allowsAddress, isWildcardAddress, urlHost } from './addresses.js'
import { LOGIN_PATH, renderLoginPage, renderMessagePage, respond, safeNext } from './gate.js'

/**
 * Owns the one socket the phone talks to.
 */
export class EntryListener {
  /**
   * @param {{ state: object, gate: object, proxy: object, tunnel: object, logger: object, copy: () => object, diagnostics?: {record: (event: string, fields?: Record<string, unknown>) => void} }} options - dependencies.
   */
  constructor({ state, gate, proxy, tunnel, logger, copy, diagnostics }) {
    this.state = state
    this.gate = gate
    this.proxy = proxy
    this.tunnel = tunnel
    this.logger = logger
    this.copy = copy
    this.diagnostics = diagnostics
    /** @type {import('node:http').Server | undefined} */
    this.server = undefined
    /** @type {'stopped' | 'listening' | 'error'} */
    this.stateName = 'stopped'
    /** @type {string | undefined} */
    this.error = undefined
    /** @type {Map<import('node:net').Socket, {sessionId?: string}>} */
    this.sockets = new Map()
  }

  /** What the settings page shows. */
  status() {
    const { host, port, enabled, allowFrom } = this.state.listener
    const boundPort = this.stateName === 'listening' && this.server !== undefined
      ? (this.server.address()?.port ?? port)
      : port
    return {
      enabled,
      host,
      port: boundPort,
      allowFrom,
      state: this.stateName,
      error: this.error,
      url: this.stateName === 'listening' ? `http://${urlHost(host) ?? host}:${boundPort}/` : undefined,
    }
  }

  /**
   * Serve the listener.
   * @param {{host: string, port: number}} want - where to listen.
   * @returns {Promise<import('node:http').Server>}
   */
  listen(want) {
    const server = http.createServer((request, response) => {
      this.handle(request, response).catch((error) => {
        this.logger.error(`dsh-remote-control: request failed: ${error instanceof Error ? error.message : String(error)}`)
        if (!response.headersSent) respond(response, 500, { 'content-type': 'text/plain; charset=utf-8' }, 'Internal error\n')
        else response.destroy()
      })
    })
    server.on('connection', (socket) => {
      this.sockets.set(socket, {})
      socket.once('close', () => this.sockets.delete(socket))
    })
    server.on('upgrade', (request, socket, head) => {
      this.handleUpgrade(request, socket, head).catch(() => socket.destroy())
    })
    server.keepAliveTimeout = 65_000
    server.requestTimeout = 0

    return new Promise((resolve, reject) => {
      const onError = (error) => {
        server.removeListener('listening', onListening)
        reject(error)
      }
      const onListening = () => {
        server.removeListener('error', onError)
        server.on('error', (error) => {
          this.error = error.message
          this.stateName = 'error'
          this.logger.error(`dsh-remote-control: entry listener error: ${error.message}`)
        })
        resolve(server)
      }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(want.port, want.host)
    })
  }

  /**
   * Apply a new configuration, rebinding only when the address changed.
   * @param {{enabled: boolean, host: string, port: number, allowFrom?: string[]}} next - desired state.
   * @returns {Promise<{ok: boolean, code?: string, message?: string}>}
   */
  async apply(next) {
    const want = {
      enabled: next.enabled === true,
      host: typeof next.host === 'string' ? next.host : '',
      port: Number(next.port),
      allowFrom: Array.isArray(next.allowFrom) ? next.allowFrom : this.state.listener.allowFrom,
    }
    if (want.enabled) {
      if (!Number.isInteger(want.port) || want.port < 0 || want.port > 65_535) {
        return { ok: false, code: 'invalid-port', message: 'The port must be a whole number between 1 and 65535.' }
      }
      if (isWildcardAddress(want.host) || urlHost(want.host) === undefined) {
        return {
          ok: false,
          code: 'invalid-host',
          message: 'Choose one concrete address of this machine; a wildcard address would open every interface.',
        }
      }
      if (!this.state.hasPassword() && this.state.invites.length === 0) {
        return {
          ok: false,
          code: 'no-credential',
          message: 'Set the permanent password (or mint an invite) before opening the entry.',
        }
      }
    }

    const unchanged = want.enabled === (this.stateName === 'listening')
      && want.host === this.state.listener.host
      && want.port === this.state.listener.port
      && JSON.stringify(want.allowFrom) === JSON.stringify(this.state.listener.allowFrom)

    if (!want.enabled) {
      await this.stop()
      this.state.setListener({ ...want, enabled: false })
      return { ok: true }
    }

    if (unchanged) return { ok: true }

    const sameAddress = want.host === this.state.listener.host && want.port === this.state.listener.port
    let candidate
    try {
      if (sameAddress) {
        // Rebinding one address: the old socket must go first.
        await this.stop()
        candidate = await this.listen(want)
      } else {
        // Rebind: prove the new address works before giving up the old one.
        candidate = await this.listen(want)
      }
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : 'bind-failed'
      const message = error instanceof Error ? error.message : String(error)
      this.error = message
      this.stateName = this.server === undefined ? 'error' : this.stateName
      this.logger.error(`dsh-remote-control: cannot bind ${want.host}:${want.port}: ${message}`)
      return { ok: false, code, message }
    }

    if (!sameAddress) await this.stop()
    this.server = candidate
    this.stateName = 'listening'
    this.error = undefined
    // Record the port the socket actually got, so an OS-assigned port stays
    // stable across restarts instead of being re-drawn next boot.
    const boundPort = candidate.address()?.port ?? want.port
    this.state.setListener({ ...want, port: boundPort, enabled: true })
    this.logger.info(`dsh-remote-control: entry listening on http://${urlHost(want.host) ?? want.host}:${boundPort}/`)
    return { ok: true }
  }

  /** Close the listener and every socket it owns. */
  async stop() {
    const server = this.server
    this.server = undefined
    this.stateName = 'stopped'
    if (server !== undefined) {
      await new Promise((resolve) => {
        server.close(() => resolve())
        server.closeAllConnections?.()
        setTimeout(resolve, 2000).unref?.()
      })
    }
    for (const socket of this.sockets.keys()) socket.destroy()
    this.sockets.clear()
    this.gate.closeAllSockets()
  }

  /** Serve one HTTP request. */
  async handle(request, response) {
    if (!this.allowed(request, response)) return
    if (await this.gate.handle(request, response)) return

    const authenticated = this.gate.authenticate(request)
    if (authenticated === undefined) {
      const path = String(request.url ?? '/')
      const wantsJson = path.startsWith('/api/')
        || String(request.headers.accept ?? '').includes('application/json')
      if (wantsJson) {
        // A fetch that suddenly receives an HTML page reports a parse error and
        // hides the real cause; an explicit 401 lets the page reload into login.
        respond(response, 401, { 'content-type': 'application/json; charset=utf-8' },
          JSON.stringify({ error: { code: 'remote-control/not-signed-in', message: 'Sign in again at the entry page.' } }))
        return
      }
      respond(response, 200, { 'content-type': 'text/html; charset=utf-8' }, renderLoginPage({
        ...this.copy(),
        action: `${LOGIN_PATH}?next=${encodeURIComponent(safeNext(path))}`,
      }))
      return
    }
    // Track the socket so revoking this session also aborts in-flight HTTP
    // responses (a streamed download or an event stream), not only WebSockets.
    this.sockets.set(request.socket, { sessionId: authenticated.session.id })
    this.gate.track(authenticated.session.id, request.socket)
    await this.proxy.handle(request, response)
  }

  /** Serve one WebSocket upgrade. */
  async handleUpgrade(request, socket, head) {
    const trace = (event, fields = {}) => this.diagnostics?.record(event, {
      path: request.url,
      address: request.socket?.remoteAddress,
      agent: request.headers['user-agent'],
      hasCookie: request.headers.cookie !== undefined,
      ...fields,
    })
    trace('upgrade')
    if (!this.allowed(request)) {
      trace('upgrade-refused', { reason: 'not-allowed' })
      socket.write('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\nforbidden')
      socket.destroy()
      return
    }
    const authenticated = this.gate.authenticate(request)
    if (authenticated === undefined) {
      trace('upgrade-refused', { reason: 'no-session' })
      socket.write(`HTTP/1.1 401 Unauthorized\r\ncontent-type: text/html; charset=utf-8\r\nconnection: close\r\n\r\n${renderMessagePage({
        title: this.copy().title,
        heading: this.copy().title,
        message: 'Sign in first, then reload the page.',
      }).replace(/\r?\n/gu, '')}`)
      socket.destroy()
      return
    }
    this.sockets.set(socket, { sessionId: authenticated.session.id })
    await this.tunnel.handle(request, socket, head, authenticated.session)
  }

  /** Apply the source-address allow list and a Host sanity check. */
  allowed(request, response) {
    const address = request.socket?.remoteAddress ?? ''
    if (!allowsAddress(this.state.listener.allowFrom, address)) {
      this.logger.warn(`dsh-remote-control: refused ${address}; not in allowFrom`)
      if (response !== undefined) respond(response, 403, { 'content-type': 'text/plain; charset=utf-8' }, 'Not allowed\n')
      return false
    }
    return true
  }
}
