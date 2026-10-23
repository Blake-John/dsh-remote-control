/**
 * The HTTP half of the reverse proxy: rewrite the few headers the Harness
 * trust fence inspects, attach the credential this process holds on the
 * phone's behalf, and stream both directions without buffering.
 */

import http from 'node:http'
import https from 'node:https'

/** Headers that describe one hop and must not be forwarded. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * Request headers for the upstream hop.
 * @param {Record<string, string | string[] | undefined>} incoming - client headers.
 * @param {{authority: string, origin: string}} target - upstream authority and origin.
 * @param {string} cookie - the held Harness credential.
 * @returns {Record<string, string | string[]>}
 */
export function rewriteRequestHeaders(incoming, target, cookie) {
  const out = {}
  for (const [name, value] of Object.entries(incoming)) {
    const key = name.toLowerCase()
    if (value === undefined) continue
    if (HOP_BY_HOP.has(key)) continue
    if (key === 'cookie' || key === 'host' || key === 'origin' || key === 'referer') continue
    out[key] = value
  }
  // The Harness fence admits loopback and compares an attached Origin against
  // the Host it sees, so both must speak the upstream authority.
  out.host = target.authority
  out.cookie = cookie
  if (typeof incoming.origin === 'string') out.origin = target.origin.replace(/\/$/u, '')
  if (typeof incoming.referer === 'string') {
    try {
      const referer = new URL(incoming.referer)
      out.referer = `${target.origin.replace(/\/$/u, '')}${referer.pathname}${referer.search}`
    } catch {
      // A malformed Referer carries no useful path; drop it.
    }
  }
  return out
}

/**
 * Response headers for the client, with the credential and hop headers removed
 * and any absolute `Location` brought back to the client's authority.
 * @param {http.IncomingHttpHeaders} incoming - upstream headers.
 * @param {string | undefined} clientAuthority - the Host the phone used.
 * @param {{authority: string}} target - upstream authority.
 * @returns {Record<string, string | string[]>}
 */
export function rewriteResponseHeaders(incoming, clientAuthority, target) {
  const out = {}
  for (const [name, value] of Object.entries(incoming)) {
    const key = name.toLowerCase()
    if (value === undefined) continue
    if (HOP_BY_HOP.has(key)) continue
    // The phone must never hold the Harness credential; keeping it out is what
    // makes per-device revocation real.
    if (key === 'set-cookie') continue
    if (key === 'location' && typeof value === 'string' && clientAuthority !== undefined) {
      out.location = value.replace(target.authority, clientAuthority)
      continue
    }
    out[key] = value
  }
  return out
}

/**
 * Stream one client request to the Harness listener and its answer back.
 */
export class Proxy {
  /**
   * @param {{ facts: () => {protocol: string, hostname: string, port: number, authority: string, origin: string}, credential: object, logger: object, timeoutMs?: number }} options - dependencies.
   */
  constructor({ facts, credential, logger, timeoutMs = 0 }) {
    this.facts = facts
    this.credential = credential
    this.logger = logger
    this.timeoutMs = timeoutMs
  }

  /**
   * Answer one request.
   * @param {import('node:http').IncomingMessage} request - client request.
   * @param {import('node:http').ServerResponse} response - client response.
   */
  async handle(request, response) {
    let cookie
    try {
      cookie = await this.credential.ensure()
    } catch (error) {
      this.fail(response, 502, 'The Harness credential is unavailable.', error)
      return
    }
    this.forward(request, response, cookie, true)
  }

  /** Perform the upstream hop, optionally retrying once with a fresh credential. */
  forward(request, response, cookie, mayRetry) {
    let target
    try {
      target = this.facts()
    } catch (error) {
      this.fail(response, 502, 'The Harness listener address is not usable.', error)
      return
    }
    const transport = target.protocol === 'https:' ? https : http
    const clientAuthority = typeof request.headers.host === 'string' ? request.headers.host : undefined
    const headers = rewriteRequestHeaders(request.headers, target, cookie)

    const upstreamRequest = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: request.method ?? 'GET',
      path: request.url ?? '/',
      headers,
      ...target.protocol === 'https:' ? { rejectUnauthorized: false, servername: undefined } : {},
    }, (upstreamResponse) => {
      // A stored credential can be invalidated by a listener restart; re-acquire
      // once, but only for a bodyless request we can replay.
      if (upstreamResponse.statusCode === 401 && mayRetry && (request.method === 'GET' || request.method === 'HEAD')) {
        upstreamResponse.resume()
        this.credential.refresh(cookie).then((ok) => {
          if (!ok) {
            this.fail(response, 502, 'The Harness rejected the stored credential.')
            return
          }
          this.forward(request, response, this.credential.cookie, false)
        }).catch(() => this.fail(response, 502, 'The Harness rejected the stored credential.'))
        return
      }

      try {
        response.writeHead(upstreamResponse.statusCode ?? 502, rewriteResponseHeaders(
          upstreamResponse.headers,
          clientAuthority,
          target,
        ))
        response.flushHeaders?.()
      } catch {
        upstreamResponse.destroy()
        return
      }
      upstreamResponse.pipe(response)
      upstreamResponse.on('error', () => response.destroy())
    })

    if (this.timeoutMs > 0) {
      upstreamRequest.setTimeout(this.timeoutMs, () => upstreamRequest.destroy(new Error('upstream timed out')))
    }
    upstreamRequest.on('error', (error) => this.fail(response, 502, 'The Harness did not answer.', error))
    request.on('aborted', () => upstreamRequest.destroy())
    response.on('close', () => {
      if (!response.writableEnded) upstreamRequest.destroy()
    })
    request.pipe(upstreamRequest)
  }

  /** Answer a request the proxy could not complete. */
  fail(response, status, message, error) {
    if (response.headersSent) {
      response.destroy()
      return
    }
    if (error !== undefined) {
      this.logger.warn(`dsh-remote-control: proxy failure: ${error instanceof Error ? error.message : String(error)}`)
    }
    response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' })
    response.end(`${message}\n`)
  }
}
