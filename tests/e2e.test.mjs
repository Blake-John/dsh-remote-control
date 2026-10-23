/**
 * End-to-end tests: mount the plugin against a stand-in "Harness" listener and
 * drive the real entry socket — login, proxying, streaming uploads, SSE,
 * WebSocket tunnelling, revocation — over real sockets.
 *
 * The stand-in implements the parts of the Harness the plugin depends on: a
 * launch-token exchange that mints a `dsh-auth-*` cookie, a credential check on
 * every other request, and one upgrade route.
 */

import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import http from 'node:http'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, it } from 'node:test'

import { createRemoteControl, normalizeConfig } from '../index.js'
import { SESSION_COOKIE } from '../lib/state.js'

/** A promise that resolves on the next event of `name`. */
function once(emitter, name, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out waiting for ${String(name)}`)), timeoutMs)
    emitter.once(name, (...args) => {
      clearTimeout(timer)
      resolve(args)
    })
  })
}

/** Listen on an ephemeral loopback port and return the server plus its origin. */
function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({ server, port, origin: `http://127.0.0.1:${port}` })
    })
  })
}

/** The stand-in Harness: token exchange, credential check, streaming, upgrade. */
function createFixture() {
  const requests = []
  const sockets = new Set()
  const server = http.createServer((request, response) => {
    const url = new URL(String(request.url ?? '/'), 'http://fixture.invalid')
    if (url.pathname === '/' && url.searchParams.has('token')) {
      response.writeHead(302, { location: './', 'set-cookie': 'dsh-auth-fixture=ok; Path=/; HttpOnly' })
      response.end()
      return
    }
    const cookie = String(request.headers.cookie ?? '')
    if (!cookie.includes('dsh-auth-fixture=ok')) {
      response.writeHead(401, { 'content-type': 'text/plain' })
      response.end('unauthorized')
      return
    }
    requests.push({ method: request.method, url: request.url, headers: request.headers })

    if (url.pathname === '/sse') {
      response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' })
      response.write('data: one\n\n')
      setTimeout(() => {
        response.write('data: two\n\n')
        response.end()
      }, 20)
      return
    }

    if (url.pathname === '/hold') {
      response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' })
      response.write('data: held\n\n')
      request.on('close', () => response.destroy())
      return
    }

    if (url.pathname === '/echo') {
      const chunks = []
      request.on('data', chunk => chunks.push(chunk))
      request.on('end', () => {
        response.writeHead(200, {
          'content-type': 'application/json',
          // A rotated credential must never reach the phone.
          'set-cookie': 'dsh-auth-fixture=rotated; Path=/',
        })
        response.end(JSON.stringify({
          method: request.method,
          bytes: Buffer.concat(chunks).length,
          headers: request.headers,
        }))
      })
      return
    }

    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    response.end(`<html>harness ${String(request.url)}</html>`)
  })

  server.on('connection', (socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.on('error', () => socket.destroy())
  })

  server.on('upgrade', (request, socket) => {
    sockets.add(socket)
    socket.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n')
    socket.on('data', chunk => socket.write(chunk))
    socket.on('error', () => socket.destroy())
  })

  /** Close every socket the fixture still holds, so `close()` can settle. */
  const shutdown = () => new Promise((resolve) => {
    for (const socket of sockets) socket.destroy()
    sockets.clear()
    server.closeAllConnections?.()
    server.close(() => resolve())
  })

  return { server, requests, shutdown }
}

/**
 * A stand-in Harness that restarts the way the Desktop host does: a fresh
 * launch token each time and, unless the port is kept, a fresh OS-assigned port.
 */
function createRotatingFixture() {
  let epoch = 1
  let server
  let origin
  const sockets = new Set()

  const authorized = request => String(request.headers.cookie ?? '').includes(`dsh-auth-rotating=${epoch}`)

  const onRequest = (request, response) => {
    const url = new URL(String(request.url ?? '/'), 'http://fixture.invalid')
    if (url.pathname === '/' && url.searchParams.has('token')) {
      response.writeHead(302, { location: './', 'set-cookie': `dsh-auth-rotating=${epoch}; Path=/; HttpOnly` })
      response.end()
      return
    }
    if (!authorized(request)) {
      response.writeHead(401, { 'content-type': 'text/plain' })
      response.end('unauthorized')
      return
    }
    if (url.pathname === '/echo') {
      const chunks = []
      request.on('data', chunk => chunks.push(chunk))
      request.on('end', () => {
        response.writeHead(200, { 'content-type': 'application/json' })
        response.end(JSON.stringify({ epoch, bytes: Buffer.concat(chunks).length }))
      })
      return
    }
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
    response.end(`epoch ${epoch}`)
  }

  const onUpgrade = (request, socket) => {
    if (!authorized(request)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    socket.write('HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n')
    socket.on('data', chunk => socket.write(chunk))
    socket.on('error', () => socket.destroy())
  }

  const start = (port = 0) => new Promise((resolve) => {
    server = http.createServer(onRequest)
    server.on('upgrade', onUpgrade)
    server.on('connection', (socket) => {
      sockets.add(socket)
      socket.on('close', () => sockets.delete(socket))
      socket.on('error', () => socket.destroy())
    })
    server.listen(port, '127.0.0.1', () => {
      origin = `http://127.0.0.1:${server.address().port}`
      resolve()
    })
  })

  const stop = () => new Promise((resolve) => {
    for (const socket of sockets) socket.destroy()
    sockets.clear()
    server.closeAllConnections?.()
    server.close(() => resolve())
  })

  return {
    start,
    stop,
    get origin() { return origin },
    get epoch() { return epoch },
    /**
     * Mint a new launch token. `samePort` keeps the listener (a credential
     * rotation); otherwise the server rebinds on a new port, as Desktop does.
     */
    async restart({ samePort = false } = {}) {
      epoch += 1
      if (samePort) return
      await stop()
      await start(0)
    },
  }
}

/** The smallest Cordis stand-in `mount` needs. */
function createContext(fixtureOrigin, { admitted = true, credential = 'dsh-auth-fixture=ok' } = {}) {
  const readOrigin = typeof fixtureOrigin === 'function' ? fixtureOrigin : () => fixtureOrigin
  const url = new URL(readOrigin())
  const channels = new Map()
  const routes = new Map()
  const ctx = {
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    get(name) {
      if (name === 'logger') return this.logger
      return this[name]
    },
    webServer: {
      host: '127.0.0.1',
      port: Number(url.port),
      protocol: 'http:',
      getOrigin: () => readOrigin(),
      register(route) {
        assert.ok(!routes.has(route.path), `duplicate route ${route.path}`)
        routes.set(route.path, route)
        return () => routes.delete(route.path)
      },
    },
    connection: {
      authenticatedUrl: base => `${base}?token=fixture-token`,
      // Mirrors Connection's own admission: the route answers 401 when the
      // request carries no credential.
      admit(request) {
        if (!admitted) return { rejection: 401 }
        const cookie = String(request.headers.cookie ?? '')
        const accepted = typeof credential === 'function' ? credential() : credential
        return cookie.includes(accepted)
          ? { peer: { id: 'peer-1' } }
          : { rejection: 401 }
      },
      rpc: {
        // The plugin must not rely on this: it registers on the reading
        // context's webServer, which a bundle-inserted row cannot reach.
        handle() {
          throw new Error('connection.rpc.handle must not be used by this plugin')
        },
      },
    },
    effect(execute) {
      return execute()
    },
    on() {
      return () => {}
    },
    inject(_deps, callback) {
      callback(this)
    },
  }
  return { ctx, channels, routes }
}

/** Start a login and return the session cookie value. */
async function login(entryUrl, secret) {
  const response = await fetch(`${entryUrl}__rc/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ secret }),
    redirect: 'manual',
  })
  const cookies = response.headers.getSetCookie?.() ?? []
  const pair = cookies.find(line => line.startsWith(`${SESSION_COOKIE}=`))
  return {
    status: response.status,
    location: response.headers.get('location'),
    cookie: pair === undefined ? undefined : pair.split(';')[0],
  }
}

/** A recordable `ServerResponse` for direct handler calls. */
function fakeResponse() {
  const out = { status: 0, headers: {}, body: '' }
  return {
    out,
    writeHead(status, headers) {
      out.status = status
      Object.assign(out.headers, headers ?? {})
      return this
    },
    end(body) {
      out.body = body ?? ''
      return this
    },
  }
}

/** An async-iterable `IncomingMessage` for direct handler calls. */
function fakeRequest({ method = 'POST', url, headers = {}, body = '' }) {
  return {
    method,
    url,
    headers,
    async *[Symbol.asyncIterator]() {
      if (body !== '') yield Buffer.from(body)
    },
  }
}

describe('entry listener end to end', () => {
  let fixture
  let ctx
  let api
  let dir
  let routes
  let entryUrl
  let sessionCookie
  const PASSWORD = 'remote-control-passphrase'

  before(async () => {
    fixture = createFixture()
    const listening = await listen(fixture.server)
    dir = mkdtempSync(join(tmpdir(), 'dsh-remote-control-e2e-'))
    const created = createContext(listening.origin)
    ctx = created.ctx
    routes = created.routes
    api = createRemoteControl({
      ctx,
      config: normalizeConfig({ statePath: join(dir, 'state.json'), sessionDays: 30 }),
      webServer: ctx.webServer,
      connection: ctx.connection,
    })
  })

  after(async () => {
    await api.listener.stop()
    await fixture.shutdown()
    rmSync(dir, { recursive: true, force: true })
  })

  it('refuses to open the entry without a credential', async () => {
    const result = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0 })
    assert.equal(result.ok, false)
    assert.equal(result.error.code, 'remote-control/no-credential')
  })

  it('refuses a wildcard or unspellable listen address', async () => {
    const password = await api.rpc('password/set', { next: PASSWORD })
    assert.equal(password.ok, true)

    const wildcard = await api.rpc('listener/apply', { enabled: true, host: '0.0.0.0', port: 0 })
    assert.equal(wildcard.ok, false)
    assert.equal(wildcard.error.code, 'remote-control/invalid-host')

    const zoned = await api.rpc('listener/apply', { enabled: true, host: 'fe80::1%eth0', port: 0 })
    assert.equal(zoned.ok, false)
    assert.equal(zoned.error.code, 'remote-control/invalid-host')
  })

  it('binds the entry and reports its URL', async () => {
    const applied = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0 })
    assert.equal(applied.ok, true, JSON.stringify(applied))
    assert.equal(applied.value.listener.state, 'listening')
    entryUrl = applied.value.listener.url
    assert.match(entryUrl, /^http:\/\/127\.0\.0\.1:\d+\/$/u)
  })

  it('serves the login page to an unauthenticated request', async () => {
    const response = await fetch(entryUrl)
    assert.equal(response.status, 200)
    assert.match(response.headers.get('content-type'), /text\/html/u)
    const body = await response.text()
    assert.match(body, /name="secret"/u)
    assert.match(response.headers.get('cache-control'), /no-store/u)
  })

  it('refuses a wrong password and accepts the right one', async () => {
    const wrong = await login(entryUrl, 'not-the-password')
    assert.equal(wrong.status, 401)
    assert.equal(wrong.cookie, undefined)

    const right = await login(entryUrl, PASSWORD)
    assert.equal(right.status, 302)
    assert.equal(right.location, '/')
    assert.ok(right.cookie !== undefined)
    assert.match(right.cookie, new RegExp(`^${SESSION_COOKIE}=[\\w-]+\\.[\\w-]+$`, 'u'))
    sessionCookie = right.cookie
  })

  it('proxies a page with the upstream authority and the held credential', async () => {
    const before = fixture.requests.length
    const response = await fetch(`${entryUrl}?view=chat`, { headers: { cookie: sessionCookie } })
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('set-cookie'), null, 'the Harness credential never reaches the phone')
    assert.match(await response.text(), /harness \/\?view=chat/u)

    const seen = fixture.requests.at(before) ?? fixture.requests.at(-1)
    assert.equal(seen.url, '/?view=chat')
    assert.match(String(seen.headers.host), /^127\.0\.0\.1:\d+$/u, 'the Host is the upstream authority')
    assert.match(String(seen.headers.cookie), /dsh-auth-fixture=ok/u)
    assert.doesNotMatch(String(seen.headers.cookie), /dsh-rc-session/u, 'the session cookie stays at the entry')
  })

  it('streams a large upload through without buffering it away', async () => {
    const payload = Buffer.alloc(2 * 1024 * 1024, 7)
    const response = await fetch(`${entryUrl}echo`, {
      method: 'POST',
      headers: { cookie: sessionCookie, 'content-type': 'application/octet-stream' },
      body: payload,
    })
    assert.equal(response.status, 200)
    assert.equal(response.headers.get('set-cookie'), null, 'a rotated upstream cookie is dropped too')
    const body = await response.json()
    assert.equal(body.method, 'POST')
    assert.equal(body.bytes, payload.length)
    assert.match(String(body.headers.cookie), /dsh-auth-fixture=ok/u)
  })

  it('relays server-sent events as they arrive', async () => {
    const response = await fetch(`${entryUrl}sse`, { headers: { cookie: sessionCookie } })
    assert.equal(response.status, 200)
    const text = await response.text()
    assert.match(text, /data: one/u)
    assert.match(text, /data: two/u)
  })

  it('tunnels a WebSocket upgrade and pipes bytes both ways', async () => {
    const { port } = new URL(entryUrl)
    const socket = net.connect(Number(port), '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /api/remote.mux HTTP/1.1',
      `host: 127.0.0.1:${port}`,
      'connection: Upgrade',
      'upgrade: websocket',
      'sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-version: 13',
      `cookie: ${sessionCookie}`,
      '',
      '',
    ].join('\r\n'))

    let received = ''
    const settled = new Promise((resolve) => {
      socket.on('data', (chunk) => {
        received += chunk.toString('utf8')
        if (received.includes('101 Switching Protocols')) resolve()
      })
    })
    await settled
    assert.match(received, /101 Switching Protocols/u)

    socket.write('ping-through-the-tunnel')
    const echoed = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(received), 2000)
      socket.on('data', (chunk) => {
        received += chunk.toString('utf8')
        if (received.includes('ping-through-the-tunnel')) {
          clearTimeout(timer)
          resolve(received)
        }
      })
    })
    assert.match(String(echoed), /ping-through-the-tunnel/u)

    socket.destroy()
  })

  it('refuses an upgrade without a session', async () => {
    const { port } = new URL(entryUrl)
    const socket = net.connect(Number(port), '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /api/remote.mux HTTP/1.1',
      `host: 127.0.0.1:${port}`,
      'connection: Upgrade',
      'upgrade: websocket',
      'sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==',
      '',
      '',
    ].join('\r\n'))
    let received = ''
    socket.on('data', chunk => { received += chunk.toString('utf8') })
    await new Promise(resolve => setTimeout(resolve, 200))
    assert.match(received, /401/u)
    socket.destroy()
  })

  it('applies the source allow list', async () => {
    const applied = await api.rpc('listener/apply', {
      enabled: true,
      host: '127.0.0.1',
      port: 0,
      allowFrom: ['10.0.0.0/8'],
    })
    assert.equal(applied.ok, true)
    const url = applied.value.listener.url
    const refused = await fetch(url, { headers: { cookie: sessionCookie } })
    assert.equal(refused.status, 403)

    const reopened = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0, allowFrom: [] })
    assert.equal(reopened.ok, true)
    entryUrl = reopened.value.listener.url
    const allowed = await fetch(entryUrl, { headers: { cookie: sessionCookie } })
    assert.equal(allowed.status, 200)
  })

  it('keeps the stored allow list when a later apply omits it', async () => {
    const withList = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0, allowFrom: ['10.0.0.0/8'] })
    assert.equal(withList.ok, true)
    const partial = await api.rpc('listener/apply', { host: '127.0.0.1', port: 0 })
    assert.equal(partial.ok, true)
    assert.deepEqual(partial.value.listener.allowFrom, ['10.0.0.0/8'], 'a partial call must not clear the allow list')
    assert.equal(partial.value.listener.enabled, true, 'nor turn the entry off')

    const reset = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0, allowFrom: [] })
    assert.equal(reset.ok, true)
    entryUrl = reset.value.listener.url
  })

  it('revokes one device and closes its live sockets', async () => {
    const status = await api.rpc('status', {})
    const session = status.value.sessions.find(entry => entry.revokedAt === null)
    assert.ok(session !== undefined)

    // Hold an open tunnel, then revoke the session that owns it.
    const { port } = new URL(entryUrl)
    const socket = net.connect(Number(port), '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /api/remote.mux HTTP/1.1',
      `host: 127.0.0.1:${port}`,
      'connection: Upgrade',
      'upgrade: websocket',
      `cookie: ${sessionCookie}`,
      '',
      '',
    ].join('\r\n'))
    let upgraded = ''
    await new Promise((resolve) => {
      socket.on('data', (chunk) => {
        upgraded += chunk.toString('utf8')
        if (upgraded.includes('101')) resolve()
      })
      setTimeout(resolve, 1500)
    })
    assert.match(upgraded, /101/u)

    const closed = once(socket, 'close', 3000)
    const revoked = await api.rpc('sessions/revoke', { id: session.id })
    assert.equal(revoked.ok, true)
    await closed.catch(() => {})

    const after = await fetch(entryUrl, { headers: { cookie: sessionCookie } })
    assert.equal(after.status, 200)
    assert.match(await after.text(), /name="secret"/u, 'a revoked device falls back to the login page')
  })

  it('signs every device out when the password changes', async () => {
    const fresh = await login(entryUrl, PASSWORD)
    assert.equal(fresh.status, 302)
    const changed = await api.rpc('password/set', { current: PASSWORD, next: 'another-long-passphrase' })
    assert.equal(changed.ok, true)
    assert.equal(changed.value.signedOut, true)

    const after = await fetch(entryUrl, { headers: { cookie: fresh.cookie } })
    assert.match(await after.text(), /name="secret"/u)

    const relogin = await login(entryUrl, PASSWORD)
    assert.equal(relogin.status, 401, 'the old password no longer works')
    const next = await login(entryUrl, 'another-long-passphrase')
    assert.equal(next.status, 302)
    sessionCookie = next.cookie
  })

  it('accepts a one-time invite without the password', async () => {
    const invite = await api.rpc('invite/create', {})
    assert.equal(invite.ok, true)
    const viaInvite = await login(entryUrl, invite.value.code)
    assert.equal(viaInvite.status, 302)
    const replay = await login(entryUrl, invite.value.code)
    assert.equal(replay.status, 401, 'an invite works once')
  })

  it('aborts an in-flight HTTP stream when the session is revoked', async () => {
    const fresh = await login(entryUrl, 'another-long-passphrase')
    assert.equal(fresh.status, 302)
    const response = await fetch(`${entryUrl}hold`, { headers: { cookie: fresh.cookie } })
    assert.equal(response.status, 200)

    const reader = response.body.getReader()
    const first = await reader.read()
    assert.match(Buffer.from(first.value ?? new Uint8Array()).toString('utf8'), /data: held/u)

    const listed = await api.rpc('status', {})
    const target = listed.value.sessions.find(session => session.revokedAt === null && session.via === 'password')
    assert.ok(target !== undefined)
    await api.rpc('sessions/revoke', { id: target.id })

    // The socket belonging to that session must stop delivering immediately.
    let stopped = false
    try {
      const next = await reader.read()
      stopped = next.done === true
    } catch {
      stopped = true
    }
    assert.equal(stopped, true, 'revocation must end the open stream')
  })

  it('rejects a bad allow-list entry instead of storing it', async () => {
    const result = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0, allowFrom: ['not-a-cidr'] })
    assert.equal(result.ok, false)
    assert.equal(result.error.code, 'remote-control/invalid-allow-from')
  })

  it('keeps the entry off after disabling it', async () => {
    const before = entryUrl
    const disabled = await api.rpc('listener/apply', { enabled: false })
    assert.equal(disabled.ok, true)
    assert.equal(disabled.value.listener.state, 'stopped')
    await assert.rejects(fetch(before, { headers: { cookie: sessionCookie } }))
  })

  it('serves its RPC channel with a Connection-compatible envelope', async () => {
    const route = routes.get('/remoteControl')
    assert.ok(route !== undefined, 'the channel must be registered on webServer')
    assert.equal(route.kind, 'prefix')

    const envelope = (method) => JSON.stringify({ type: 'client-request', rpcId: 'rpc-1', method, payload: {} })

    // No Harness credential on the request: Connection admission refuses it.
    const denied = fakeResponse()
    route.handler(fakeRequest({ url: '/remoteControl/ping', headers: { 'content-type': 'application/json' }, body: envelope('ping') }), denied)
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(denied.out.status, 401)

    const headers = { 'content-type': 'application/json', cookie: 'dsh-auth-fixture=ok' }
    const ok = fakeResponse()
    route.handler(fakeRequest({ url: '/remoteControl/ping', headers, body: envelope('ping') }), ok)
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(ok.out.status, 200)
    const payload = JSON.parse(ok.out.body)
    assert.equal(payload.type, 'server-response')
    assert.equal(payload.rpcId, 'rpc-1')
    assert.deepEqual(payload.result, { ok: true, value: { pong: true } })

    const wrongType = fakeResponse()
    route.handler(fakeRequest({ url: '/remoteControl/ping', headers: { ...headers, 'content-type': 'text/plain' }, body: envelope('ping') }), wrongType)
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(wrongType.out.status, 415)

    const mismatch = fakeResponse()
    route.handler(fakeRequest({ url: '/remoteControl/status', headers, body: envelope('ping') }), mismatch)
    await new Promise(resolve => setTimeout(resolve, 20))
    assert.equal(mismatch.out.status, 400)
  })

  it('reports credential state and the upstream authority', async () => {
    const status = await api.rpc('status', {})
    assert.equal(status.value.upstream.ok, true)
    assert.match(status.value.upstream.authority, /^127\.0\.0\.1:\d+$/u)
    assert.equal(status.value.upstream.credential.state, 'ready')
    assert.ok(status.value.addresses.length > 0)
  })

  it('refuses an unknown method', async () => {
    const result = await api.rpc('nope', {})
    assert.equal(result.ok, false)
    assert.equal(result.error.code, 'remote-control/unknown-method')
  })
})

describe('rate limiting', () => {
  it('cools down after repeated failures from one address', async () => {
    const fixture = createFixture()
    const listening = await listen(fixture.server)
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-control-rate-'))
    const { ctx } = createContext(listening.origin)
    const api = createRemoteControl({
      ctx,
      config: normalizeConfig({ statePath: join(dir, 'state.json') }),
      webServer: ctx.webServer,
      connection: ctx.connection,
    })
    try {
      await api.rpc('password/set', { next: 'remote-control-passphrase' })
      const applied = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0 })
      const entryUrl = applied.value.listener.url

      const attempts = []
      for (let index = 0; index < 6; index += 1) {
        const result = await login(entryUrl, 'wrong')
        attempts.push(result.status)
      }
      // The fifth failure trips the cooldown, so it is already answered 429.
      assert.deepEqual(attempts.slice(0, 4), [401, 401, 401, 401])
      assert.deepEqual(attempts.slice(4), [429, 429])

      // A correct password is also refused while the cooldown holds.
      const blocked = await login(entryUrl, 'remote-control-passphrase')
      assert.equal(blocked.status, 429)
    } finally {
      await api.listener.stop()
      await fixture.shutdown()
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('a Desktop Harness that restarts', () => {
  let fixture
  let api
  let dir
  let entryUrl
  let sessionCookie
  const PASSWORD = 'desktop-restart-passphrase'

  before(async () => {
    fixture = createRotatingFixture()
    await fixture.start()
    dir = mkdtempSync(join(tmpdir(), 'dsh-remote-control-desktop-'))
    const { ctx } = createContext(() => fixture.origin, {
      credential: () => `dsh-auth-rotating=${fixture.epoch}`,
    })
    api = createRemoteControl({
      ctx,
      config: normalizeConfig({ statePath: join(dir, 'state.json'), sessionDays: 30 }),
      webServer: ctx.webServer,
      connection: ctx.connection,
    })
    assert.equal((await api.rpc('password/set', { next: PASSWORD })).ok, true)
    const applied = await api.rpc('listener/apply', { enabled: true, host: '127.0.0.1', port: 0 })
    assert.equal(applied.ok, true, JSON.stringify(applied))
    entryUrl = applied.value.listener.url
    const logged = await login(entryUrl, PASSWORD)
    assert.equal(logged.status, 302)
    sessionCookie = logged.cookie
  })

  after(async () => {
    await api.listener.stop()
    await fixture.stop()
    rmSync(dir, { recursive: true, force: true })
  })

  it('re-acquires the credential when Desktop restarts on a new port', async () => {
    const first = await fetch(`${entryUrl}echo`, { method: 'POST', headers: { cookie: sessionCookie }, body: 'one' })
    assert.equal(first.status, 200)
    assert.equal((await first.json()).epoch, 1)

    await fixture.restart()

    // A POST body cannot be replayed, so a stale cookie would surface as a 401
    // instead of a retry: the credential must be fresh before the hop.
    const second = await fetch(`${entryUrl}echo`, { method: 'POST', headers: { cookie: sessionCookie }, body: 'two' })
    assert.equal(second.status, 200, 'the restarted Harness must be reached with a fresh credential')
    assert.equal((await second.json()).epoch, 2)
  })

  it('refreshes and retries a WebSocket upgrade when only the token rotates', async () => {
    await fixture.restart({ samePort: true })

    const { port } = new URL(entryUrl)
    const socket = net.connect(Number(port), '127.0.0.1')
    await once(socket, 'connect')
    socket.write([
      'GET /api/remote.mux HTTP/1.1',
      `host: 127.0.0.1:${port}`,
      'connection: Upgrade',
      'upgrade: websocket',
      'sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-version: 13',
      `cookie: ${sessionCookie}`,
      '',
      '',
    ].join('\r\n'))

    let received = ''
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no upgrade: ${received}`)), 3000)
      socket.on('data', (chunk) => {
        received += chunk.toString('utf8')
        if (received.includes('101 Switching Protocols')) {
          clearTimeout(timer)
          resolve()
        }
      })
    })
    assert.match(received, /101 Switching Protocols/u)
    socket.destroy()
  })
})
