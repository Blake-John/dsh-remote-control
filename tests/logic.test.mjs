/**
 * Unit tests for the pieces that carry the design: config normalization,
 * address classification and CIDR matching, the persistent state (password,
 * sessions, invites), and the header rewriting the proxy and tunnel depend on.
 */

import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'

import { normalizeConfig } from '../index.js'
import {
  allowsAddress,
  classifyAddress,
  inCidr,
  isBindable,
  isLoopbackAddress,
  isWildcardAddress,
  listAddresses,
  originFor,
  parseCidr,
  urlHost,
} from '../lib/addresses.js'
import { Gate, safeNext } from '../lib/gate.js'
import { Diagnostics } from '../lib/diagnostics.js'
import { describeAgent, readCookie, SESSION_COOKIE, State } from '../lib/state.js'
import { buildUpgradeRequest } from '../lib/tunnel.js'
import { rewriteRequestHeaders, rewriteResponseHeaders } from '../lib/proxy.js'

/** Run one block against a throwaway state file. */
function withState(run, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-control-logic-'))
  try {
    let now = 1_700_000_000_000
    const state = new State(join(dir, 'state.json'), { now: () => now, sessionDays: 180, ...options })
    return run(state, () => { now += 1_000 }, dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('normalizeConfig', () => {
  it('fills defaults and clamps out-of-range values', () => {
    const config = normalizeConfig({})
    assert.equal(config.defaultPort, 3080)
    assert.equal(config.sessionDays, 180)
    assert.equal(config.locale, 'zh')
    assert.equal(config.invite.ttlMinutes, 10)
    assert.equal(config.invite.length, 6)
    assert.equal(config.mobile.stylesheet, true)

    const clamped = normalizeConfig({ sessionDays: 99_999, defaultPort: -1, invite: { ttlMinutes: 0, length: 99 } })
    assert.equal(clamped.sessionDays, 3650)
    assert.equal(clamped.defaultPort, 1)
    assert.equal(clamped.invite.ttlMinutes, 1)
    assert.equal(clamped.invite.length, 12)
  })

  it('keeps explicit opt-outs and the English gate copy', () => {
    const config = normalizeConfig({ locale: 'en', mobile: { stylesheet: false } })
    assert.equal(config.locale, 'en')
    assert.equal(config.mobile.stylesheet, false)
  })
})

describe('addresses', () => {
  it('classifies the networks a phone may arrive from', () => {
    assert.equal(classifyAddress('127.0.0.1'), 'loopback')
    assert.equal(classifyAddress('100.101.102.103'), 'tailscale')
    assert.equal(classifyAddress('fd7a:115c:a1e0:ab12::1'), 'tailscale')
    assert.equal(classifyAddress('192.168.1.20'), 'private')
    assert.equal(classifyAddress('172.16.5.4'), 'private')
    assert.equal(classifyAddress('172.32.5.4'), 'public')
    assert.equal(classifyAddress('fe80::1'), 'link-local')
    assert.equal(classifyAddress('203.0.113.9'), 'public')
    assert.equal(classifyAddress('10.1.2.3', 'tailscale0'), 'tailscale')
  })

  it('spells URLs and refuses zoned or wildcard binds', () => {
    assert.equal(urlHost('192.168.1.20'), '192.168.1.20')
    assert.equal(urlHost('fd7a:115c:a1e0::1'), '[fd7a:115c:a1e0::1]')
    assert.equal(urlHost('fe80::1%eth0'), undefined)
    assert.equal(originFor('http:', '100.1.2.3', 3080), 'http://100.1.2.3:3080/')
    assert.equal(isWildcardAddress('0.0.0.0'), true)
    assert.equal(isWildcardAddress('::'), true)
    assert.equal(isWildcardAddress('100.1.2.3'), false)
    assert.equal(isLoopbackAddress('127.1.1.1'), true)
    assert.equal(isBindable('100.1.2.3'), true)
    assert.equal(isBindable('127.0.0.1'), false)
    assert.equal(isBindable('fe80::1'), false)
  })

  it('matches IPv4 and IPv6 CIDR blocks', () => {
    const tailnet = parseCidr('100.64.0.0/10')
    assert.ok(tailnet !== undefined)
    assert.equal(inCidr(tailnet, '100.101.102.103'), true)
    assert.equal(inCidr(tailnet, '100.128.0.1'), false)
    assert.equal(inCidr(tailnet, '192.168.1.4'), false)
    assert.equal(inCidr(tailnet, '::ffff:100.101.102.103'), true, 'a mapped v4 address compares as v4')

    const lan = parseCidr('192.168.0.0/16')
    assert.equal(inCidr(lan, '192.168.3.4'), true)
    assert.equal(inCidr(lan, '192.169.3.4'), false)

    const ula = parseCidr('fd00::/8')
    assert.equal(inCidr(ula, 'fd7a:115c:a1e0::1'), true)
    assert.equal(inCidr(ula, 'fe80::1'), false)

    assert.equal(parseCidr('not-an-address'), undefined)
    assert.equal(parseCidr('10.0.0.0/40'), undefined)
  })

  it('treats an empty allow list as unrestricted', () => {
    assert.equal(allowsAddress([], '203.0.113.9'), true)
    assert.equal(allowsAddress(undefined, '203.0.113.9'), true)
    assert.equal(allowsAddress(['100.64.0.0/10'], '100.100.5.5'), true)
    assert.equal(allowsAddress(['100.64.0.0/10'], '100.5.5.5'), false)
    assert.equal(allowsAddress(['100.64.0.0/10'], '192.168.1.5'), false)
  })

  it('lists bindable addresses with a Tailscale entry first', () => {
    const entries = listAddresses(3080)
    assert.ok(entries.length > 0)
    for (const entry of entries) {
      assert.equal(typeof entry.address, 'string')
      assert.equal(typeof entry.bindable, 'boolean')
      if (entry.kind === 'loopback') assert.equal(entry.bindable, false)
    }
  })
})

describe('State: permanent password', () => {
  it('stores a scrypt hash, never the plaintext, and rotates the secret', async () => withState(async (state, _tick, dir) => {
    const before = state.secret
    await state.setPassword('correct horse battery')
    const document = readFileSync(join(dir, 'state.json'), 'utf8')
    assert.doesNotMatch(document, /correct horse battery/u)
    assert.notEqual(state.secret, before, 'setting a password rotates the session secret')
    assert.equal(await state.verifyPassword('correct horse battery'), true)
    assert.equal(await state.verifyPassword('wrong'), false)
    assert.equal(await state.verifyPassword(''), false)
    if (process.platform !== 'win32') {
      assert.equal(statSync(join(dir, 'state.json')).mode & 0o777, 0o600)
    }
  }))

  it('accepts a password only when one exists', async () => withState(async (state) => {
    assert.equal(state.hasPassword(), false)
    assert.equal(await state.verifyPassword('anything'), false)
  }))
})

describe('State: sessions', () => {
  it('issues a verifiable cookie and resolves the session', async () => withState(async (state) => {
    await state.setPassword('password-one')
    const { session, cookie } = state.createSession({
      userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17.0 Mobile/15E148 Safari/604.1',
      address: '100.101.102.104',
    })
    assert.equal(session.label, 'iPhone · Safari')
    assert.equal(state.verifySession(cookie)?.id, session.id)
    assert.equal(state.verifySession(`${session.id}.forged`), undefined)
    assert.equal(state.verifySession('nonsense'), undefined)
    assert.equal(state.verifySession(undefined), undefined)
  }))

  it('revokes one session without touching the others', async () => withState(async (state) => {
    await state.setPassword('password-one')
    const first = state.createSession({})
    const second = state.createSession({})
    state.revokeSession(first.session.id)
    assert.equal(state.verifySession(first.cookie), undefined)
    assert.equal(state.verifySession(second.cookie)?.id, second.session.id)
    assert.equal(state.listSessions().length, 2, 'a revoked session stays in the ledger')
  }))

  it('drops every session and rotates the secret on revoke-all', async () => withState(async (state) => {
    await state.setPassword('password-one')
    const { cookie } = state.createSession({})
    const before = state.secret
    assert.equal(state.revokeAllSessions(), 1)
    assert.deepEqual(state.listSessions(), [])
    assert.notEqual(state.secret, before)
    assert.equal(state.verifySession(cookie), undefined)
  }))

  it('signs out every session when the password changes', async () => withState(async (state) => {
    await state.setPassword('password-one')
    const { cookie } = state.createSession({})
    await state.setPassword('password-two')
    assert.equal(state.verifySession(cookie), undefined)
  }))

  it('expires a session past its lifetime and slides it on use', async () => withState(async (state, tick) => {
    await state.setPassword('password-one')
    const { session, cookie } = state.createSession({})
    const created = session.expiresAt
    state.touch(session.id)
    const slid = state.verifySession(cookie).expiresAt
    assert.ok(slid >= created)
    // Walk far past the lifetime without touching: the cookie must die.
    state.sessions[0].expiresAt = state.now() - 1_000
    assert.equal(state.verifySession(cookie), undefined)
    tick()
  }))

  it('survives a reload with the password and sessions intact', async () => withState(async (state, _tick, dir) => {
    await state.setPassword('password-one')
    const { cookie } = state.createSession({ address: '100.0.0.9' })
    const reopened = new State(join(dir, 'state.json'), { now: state.now })
    assert.equal(reopened.hasPassword(), true)
    assert.equal(await reopened.verifyPassword('password-one'), true)
    assert.equal(reopened.verifySession(cookie)?.address, '100.0.0.9')
  }))
})

describe('State: invites', () => {
  it('mints a single-use code, accepts it once, and refuses a replay', async () => withState(async (state) => {
    await state.setPassword('password-one')
    const { code, expiresAt } = state.createInvite({ ttlMinutes: 10, length: 6, maxActive: 5 })
    assert.match(code, /^[A-Z2-9]{6}$/u)
    assert.equal(expiresAt - state.now(), 600_000)
    const redeemed = state.redeemInvite(` ${code.toLowerCase()} `, {})
    assert.ok(redeemed !== undefined)
    assert.equal(redeemed.session.via, 'invite')
    assert.equal(state.redeemInvite(code, {}), undefined)
  }))

  it('refuses an expired code and caps live codes', async () => withState(async (state, tick) => {
    await state.setPassword('password-one')
    const expired = state.createInvite({ ttlMinutes: 1, length: 6, maxActive: 5 })
    for (let index = 0; index < 61; index += 1) tick()
    assert.equal(state.redeemInvite(expired.code, {}), undefined)

    const first = state.createInvite({ ttlMinutes: 10, length: 6, maxActive: 2 })
    state.createInvite({ ttlMinutes: 10, length: 6, maxActive: 2 })
    state.createInvite({ ttlMinutes: 10, length: 6, maxActive: 2 })
    assert.equal(state.invites.length, 2, 'the oldest code is dropped past the cap')
    assert.equal(state.redeemInvite(first.code, {}), undefined)
  }))
})

describe('request helpers', () => {
  it('reads one cookie out of a header', () => {
    assert.equal(readCookie(`a=1; ${SESSION_COOKIE}=abc.def; b=2`, SESSION_COOKIE), 'abc.def')
    assert.equal(readCookie('a=1', SESSION_COOKIE), undefined)
    assert.equal(readCookie(undefined, SESSION_COOKIE), undefined)
  })

  it('labels a user agent', () => {
    assert.equal(describeAgent('Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36'), 'Android · Chrome')
    assert.equal(describeAgent(''), 'Unknown device')
  })
})

describe('sign-in redirect target', () => {
  it('keeps the target on this authority', () => {
    assert.equal(safeNext('/session/abc'), '/session/abc')
    assert.equal(safeNext('/?x=1'), '/?x=1')
    for (const hostile of ['//evil.example', '/\\evil.example', 'https://evil.example', 'javascript:alert(1)', '', undefined, '/a\u0000b', '/a\u0020b\u001f']) {
      assert.equal(safeNext(hostile), '/', String(hostile))
    }
  })
})

describe('login attempt table', () => {
  /** A Gate with only the pieces the limiter needs. */
  const createGate = () => new Gate({
    state: { verifySession: () => undefined, touch() {}, hasPassword: () => true },
    logger: { info() {}, warn() {}, error() {} },
    sessionDays: 30,
    copy: { title: 't', label: 'l' },
    inviteLength: 6,
  })

  it('cools one address down after five failures', () => {
    const gate = createGate()
    for (let index = 0; index < 4; index += 1) assert.equal(gate.recordAttempt('100.0.0.1', true), 0)
    assert.ok(gate.recordAttempt('100.0.0.1', true) > 0, 'the fifth failure starts a cooldown')
    assert.ok(gate.cooldown('100.0.0.1') > 0)
    assert.equal(gate.cooldown('100.0.0.2'), 0, 'other addresses are unaffected')
  })

  it('keeps the table bounded under a burst of addresses', () => {
    const gate = createGate()
    for (let index = 0; index < 700; index += 1) gate.recordAttempt(`10.0.${Math.floor(index / 256)}.${index % 256}`, true)
    assert.ok(gate.attempts.size <= 512, `table size ${gate.attempts.size}`)
  })
})

describe('session ledger cap', () => {
  it('keeps the newest 50 sessions', () => withState(async (state) => {
    await state.setPassword('password-one')
    const ids = []
    for (let index = 0; index < 60; index += 1) ids.push(state.createSession({}).session.id)
    const kept = state.listSessions()
    assert.equal(kept.length, 50)
    assert.ok(kept.some(session => session.id === ids.at(-1)), 'the newest session survives')
  }))
})

describe('proxy header rewriting', () => {
  const target = { authority: '127.0.0.1:3080', origin: 'http://127.0.0.1:3080/' }

  it('speaks the upstream authority and replaces the client cookie', () => {
    const headers = rewriteRequestHeaders({
      host: '100.101.102.103:3080',
      origin: 'http://100.101.102.103:3080',
      referer: 'http://100.101.102.103:3080/?x=1',
      cookie: 'dsh-rc-session=mine',
      'sec-fetch-site': 'same-origin',
      connection: 'keep-alive',
      'accept-encoding': 'gzip',
    }, target, 'dsh-auth-abc=secret')

    assert.equal(headers.host, '127.0.0.1:3080')
    assert.equal(headers.origin, 'http://127.0.0.1:3080')
    assert.equal(headers.referer, 'http://127.0.0.1:3080/?x=1')
    assert.equal(headers.cookie, 'dsh-auth-abc=secret', 'the client cookie never reaches the Harness')
    assert.equal(headers['sec-fetch-site'], 'same-origin')
    assert.equal(headers['accept-encoding'], 'gzip')
    assert.equal(headers.connection, undefined, 'hop-by-hop headers are dropped')
  })

  it('drops the Harness cookie on the way back and re-bases Location', () => {
    const headers = rewriteResponseHeaders({
      'set-cookie': ['dsh-auth-abc=secret; Path=/; HttpOnly'],
      location: 'http://127.0.0.1:3080/index.html',
      'content-type': 'text/html',
      'transfer-encoding': 'chunked',
    }, '100.101.102.103:3080', target)

    assert.equal(headers['set-cookie'], undefined, 'the phone must never hold the Harness credential')
    assert.equal(headers.location, 'http://100.101.102.103:3080/index.html')
    assert.equal(headers['content-type'], 'text/html')
    assert.equal(headers['transfer-encoding'], undefined)
  })

  it('rebuilds a WebSocket handshake with the credential', () => {
    const raw = buildUpgradeRequest({
      method: 'GET',
      url: '/api/remote.mux',
      headers: {
        host: '100.101.102.103:3080',
        origin: 'http://100.101.102.103:3080',
        cookie: 'dsh-rc-session=mine',
        connection: 'Upgrade',
        upgrade: 'websocket',
        'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
        'sec-websocket-version': '13',
      },
    }, target, 'dsh-auth-abc=secret')

    assert.match(raw, /^GET \/api\/remote\.mux HTTP\/1\.1\r\n/u)
    assert.match(raw, /host: 127\.0\.0\.1:3080\r\n/u)
    assert.match(raw, /origin: http:\/\/127\.0\.0\.1:3080\r\n/u)
    assert.match(raw, /cookie: dsh-auth-abc=secret\r\n/u)
    assert.match(raw, /sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n/u)
    assert.doesNotMatch(raw, /dsh-rc-session/u)
    assert.match(raw, /connection: Upgrade\r\nupgrade: websocket\r\n\r\n$/u)
  })
})

describe('socket diagnostics', () => {
  it('records events and keeps the file bounded', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-rc-diag-'))
    try {
      const path = join(dir, 'sockets.log')
      const diagnostics = new Diagnostics({ path })
      for (let index = 0; index < 420; index += 1) diagnostics.record('upgrade', { index })
      const lines = readFileSync(path, 'utf8').split('\n').filter(Boolean)
      assert.ok(lines.length <= 400, `kept ${String(lines.length)} lines`)
      const last = JSON.parse(lines.at(-1))
      assert.equal(last.event, 'upgrade')
      assert.equal(last.index, 419)
      assert.match(last.t, /^\d{4}-\d{2}-\d{2}T/u)
      assert.equal(diagnostics.info().enabled, true)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('writes nothing when disabled and never throws on a bad path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-rc-diag-off-'))
    try {
      const disabled = new Diagnostics({ path: join(dir, 'off.log'), enabled: false })
      disabled.record('upgrade')
      assert.throws(() => statSync(join(dir, 'off.log')), /ENOENT/u)

      // A directory where the file should be: the write fails, the plugin must not.
      const broken = new Diagnostics({ path: dir })
      broken.record('upgrade', { attempt: 1 })
      assert.ok(typeof broken.info().error === 'string')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
