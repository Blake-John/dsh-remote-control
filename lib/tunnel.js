/**
 * The WebSocket half of the reverse proxy.
 *
 * A Harness page keeps one mux socket open (`/api/remote.mux`) for live
 * session events, so the entry listener tunnels the upgrade as raw bytes: the
 * handshake is rebuilt with the credential and rewritten authority, then both
 * sockets are piped together. No frame parsing happens here, which keeps the
 * tunnel independent of the protocol version above it.
 */

import net from 'node:net'
import tls from 'node:tls'

/** Headers rebuilt for the upstream handshake; everything else is copied. */
const REPLACED = new Set(['host', 'origin', 'cookie', 'referer', 'connection', 'upgrade'])

/**
 * Build the upstream handshake request text.
 * @param {{method?: string, url?: string, headers: Record<string, string | string[] | undefined>}} request - client upgrade request.
 * @param {{authority: string, origin: string}} target - upstream authority and origin.
 * @param {string} cookie - held Harness credential.
 * @returns {string} the raw request head.
 */
export function buildUpgradeRequest(request, target, cookie) {
  const lines = [`${request.method ?? 'GET'} ${request.url ?? '/'} HTTP/1.1`]
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined) continue
    const key = name.toLowerCase()
    if (REPLACED.has(key)) continue
    if (Array.isArray(value)) {
      for (const item of value) lines.push(`${key}: ${item}`)
      continue
    }
    lines.push(`${key}: ${value}`)
  }
  lines.push(`host: ${target.authority}`)
  lines.push(`cookie: ${cookie}`)
  if (typeof request.headers.origin === 'string') {
    lines.push(`origin: ${target.origin.replace(/\/$/u, '')}`)
  }
  lines.push('connection: Upgrade')
  lines.push('upgrade: websocket')
  return `${lines.join('\r\n')}\r\n\r\n`
}

/**
 * Tunnel WebSocket upgrades to the Harness listener.
 */
export class Tunnel {
  /**
   * @param {{facts: () => {protocol: string, hostname: string, port: number, authority: string, origin: string}, credential: object, logger: object, gate: object}} options - dependencies.
   */
  constructor({ facts, credential, logger, gate, connectTimeoutMs = 8000 }) {
    this.facts = facts
    this.credential = credential
    this.logger = logger
    this.gate = gate
    this.connectTimeoutMs = connectTimeoutMs
  }

  /**
   * Open the tunnel for one upgrade.
   * @param {import('node:http').IncomingMessage} request - client upgrade request.
   * @param {import('node:stream').Duplex} socket - client socket.
   * @param {Buffer} head - bytes the client already sent.
   * @param {{id: string}} session - the authenticated session, tracked for revocation.
   */
  async handle(request, socket, head, session) {
    let cookie
    try {
      cookie = await this.credential.ensure()
    } catch (error) {
      this.reject(socket, 502, 'The Harness credential is unavailable.', error)
      return
    }
    const target = this.facts()
    const upstream = target.protocol === 'https:'
      ? tls.connect({ host: target.hostname, port: target.port, rejectUnauthorized: false, servername: undefined })
      : net.connect({ host: target.hostname, port: target.port })

    this.gate.track(session.id, socket)

    const connectTimer = setTimeout(() => fail(new Error('upstream connect timed out')), this.connectTimeoutMs)
    const fail = (error) => {
      clearTimeout(connectTimer)
      this.reject(socket, 502, 'The Harness did not accept the tunnel.', error)
      upstream.destroy()
    }
    upstream.once('error', fail)
    socket.once('error', () => upstream.destroy())
    socket.once('close', () => upstream.destroy())
    upstream.once('close', () => {
      if (!socket.destroyed) socket.destroy()
    })

    upstream.once('connect', () => {
      clearTimeout(connectTimer)
      upstream.removeListener('error', fail)
      upstream.on('error', () => socket.destroy())
      upstream.write(buildUpgradeRequest(request, target, cookie))
      if (head !== undefined && head.length > 0) upstream.write(head)
      // Both directions are opaque: the handshake response and every frame
      // after it pass through untouched.
      upstream.pipe(socket)
      socket.pipe(upstream)
    })
  }

  /** Answer an upgrade we cannot serve. */
  reject(socket, status, message, error) {
    if (error !== undefined) {
      this.logger.warn(`dsh-remote-control: tunnel failure: ${error instanceof Error ? error.message : String(error)}`)
    }
    try {
      socket.write(`HTTP/1.1 ${status} ${status === 502 ? 'Bad Gateway' : 'Forbidden'}\r\ncontent-type: text/plain\r\ncontent-length: ${Buffer.byteLength(message)}\r\nconnection: close\r\n\r\n${message}`)
    } catch {
      // The socket is already gone.
    }
    socket.destroy()
  }
}
