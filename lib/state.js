/**
 * Persistent plugin state: the entry listener configuration, the permanent
 * password hash, per-device sessions, and single-use invite codes.
 *
 * One JSON document, written atomically with `0600`. The document's `secret`
 * signs session cookies, so rotating it (revoke-all, password change)
 * invalidates every issued cookie at once.
 */

import { createHash, createHmac, randomBytes, randomUUID, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)

/** The session cookie the entry listener issues. */
export const SESSION_COOKIE = 'dsh-rc-session'

/** Unambiguous alphabet for invite codes: no 0/O, 1/I/L. */
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

/** scrypt cost: interactive-login weight, deliberately not tunable from the UI. */
const SCRYPT = { N: 16_384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }

/** Field sizes kept small so the state file stays readable. */
const KEY_BYTES = 32

/** Session activity writes coalesce to one per session per interval. */
const TOUCH_INTERVAL_MS = 60_000

/** Lower bound on a session lifetime, even when misconfigured. */
const MIN_SESSION_DAYS = 1

/** Newest sessions kept; older ones are dropped so the ledger cannot grow forever. */
const MAX_SESSIONS = 50

/** Human label from a User-Agent, for a session's first draft name. */
export function describeAgent(userAgent) {
  if (typeof userAgent !== 'string' || userAgent === '') return 'Unknown device'
  const platform = /iPhone/u.test(userAgent) ? 'iPhone'
    : /iPad/u.test(userAgent) ? 'iPad'
      : /Android/u.test(userAgent) ? 'Android'
        : /Macintosh/u.test(userAgent) ? 'Mac'
          : /Windows/u.test(userAgent) ? 'Windows'
            : /Linux/u.test(userAgent) ? 'Linux'
              : 'Device'
  const browser = /EdgA?\//u.test(userAgent) ? 'Edge'
    : /OPR\//u.test(userAgent) ? 'Opera'
      : /Firefox\//u.test(userAgent) ? 'Firefox'
        : /CriOS\//u.test(userAgent) ? 'Chrome'
          : /Chrome\//u.test(userAgent) ? 'Chrome'
            : /Safari\//u.test(userAgent) ? 'Safari'
              : 'Browser'
  return `${platform} · ${browser}`
}

/** Parse one cookie out of a `Cookie` header. */
export function readCookie(header, cookieName) {
  if (typeof header !== 'string' || header === '') return undefined
  for (const part of header.split(';')) {
    const separator = part.indexOf('=')
    if (separator === -1) continue
    if (part.slice(0, separator).trim() !== cookieName) continue
    return decodeURIComponent(part.slice(separator + 1).trim())
  }
  return undefined
}

/** Uniform draw from the invite alphabet. */
function randomCode(length) {
  const bytes = randomBytes(length * 2)
  let out = ''
  for (const byte of bytes) {
    if (out.length >= length) break
    const limit = 256 - (256 % CODE_ALPHABET.length)
    if (byte >= limit) continue
    out += CODE_ALPHABET[byte % CODE_ALPHABET.length]
  }
  return out.length === length ? out : randomCode(length)
}

/** Hash an invite code so a leaked state file cannot mint sessions. */
function hashCode(code) {
  return createHash('sha256').update(code.toUpperCase()).digest('base64url')
}

/** Compare two base64url digests without leaking position. */
function digestMatches(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const left = Buffer.from(a)
  const right = Buffer.from(b)
  return left.length === right.length && timingSafeEqual(left, right)
}

/** Integer clamp used by the config surface. */
export function clampInt(value, fallback, min, max) {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(parsed)))
}

/**
 * The plugin's durable state.
 */
export class State {
  /**
   * @param {string | undefined} statePath - absolute file path, or undefined for memory only.
   * @param {{ now?: () => number, sessionDays?: number }} [options] - clock and session lifetime.
   */
  constructor(statePath, options = {}) {
    this.statePath = statePath
    this.now = options.now ?? (() => Date.now())
    this.sessionDays = Math.max(MIN_SESSION_DAYS, options.sessionDays ?? 180)
    this.secret = ''
    this.listener = { enabled: false, host: '', port: 3080, allowFrom: [] }
    this.password = undefined
    this.sessions = []
    this.invites = []
    this.touched = new Map()
    this.load()
  }

  /** Read the persisted document, inventing a secret on first run. */
  load() {
    let parsed
    if (this.statePath !== undefined) {
      try {
        parsed = JSON.parse(readFileSync(this.statePath, 'utf8'))
      } catch {
        parsed = undefined
      }
    }
    if (parsed !== null && typeof parsed === 'object' && parsed.version === 2) {
      this.secret = typeof parsed.secret === 'string' ? parsed.secret : ''
      const listener = parsed.listener !== null && typeof parsed.listener === 'object' ? parsed.listener : {}
      this.listener = {
        enabled: listener.enabled === true,
        host: typeof listener.host === 'string' ? listener.host : '',
        port: clampInt(listener.port, 3080, 1, 65_535),
        allowFrom: Array.isArray(listener.allowFrom) ? listener.allowFrom.filter(entry => typeof entry === 'string') : [],
      }
      const password = parsed.password !== null && typeof parsed.password === 'object' ? parsed.password : undefined
      this.password = password !== undefined && typeof password.hash === 'string' && typeof password.salt === 'string'
        ? { salt: password.salt, hash: password.hash, updatedAt: Number(password.updatedAt) || 0 }
        : undefined
      this.sessions = Array.isArray(parsed.sessions)
        ? parsed.sessions.filter(entry => entry !== null && typeof entry === 'object' && typeof entry.id === 'string')
        : []
      this.invites = Array.isArray(parsed.invites)
        ? parsed.invites.filter(entry => entry !== null && typeof entry === 'object' && typeof entry.hash === 'string')
        : []
    }
    if (this.secret === '') {
      this.secret = randomBytes(KEY_BYTES).toString('base64url')
      this.save()
    }
  }

  /** Persist the whole document atomically; a write failure never breaks the gate. */
  save() {
    if (this.statePath === undefined) return
    try {
      mkdirSync(dirname(this.statePath), { recursive: true })
      const body = JSON.stringify({
        version: 2,
        secret: this.secret,
        listener: this.listener,
        ...this.password === undefined ? {} : { password: this.password },
        sessions: this.sessions,
        invites: this.invites,
      }, null, 2)
      const staging = `${this.statePath}.${process.pid}.tmp`
      writeFileSync(staging, body, { mode: 0o600 })
      renameSync(staging, this.statePath)
    } catch {
      // A read-only or full disk must not take the entry listener down.
    }
  }

  /** Store the listener configuration. */
  setListener(next) {
    this.listener = {
      enabled: next.enabled === true,
      host: typeof next.host === 'string' ? next.host : '',
      port: clampInt(next.port, this.listener.port, 1, 65_535),
      allowFrom: Array.isArray(next.allowFrom) ? next.allowFrom.filter(entry => typeof entry === 'string') : [],
    }
    this.save()
    return this.listener
  }

  /** Whether a permanent password exists. */
  hasPassword() {
    return this.password !== undefined
  }

  /**
   * Replace the permanent password and invalidate every session.
   * @param {string} next - the plaintext password; never stored or logged.
   * @returns the password record's `updatedAt`.
   */
  async setPassword(next) {
    const salt = randomBytes(16)
    const derived = await scrypt(next, salt, 64, SCRYPT)
    this.password = {
      salt: salt.toString('base64url'),
      hash: Buffer.from(derived).toString('base64url'),
      updatedAt: this.now(),
    }
    // A rotated secret invalidates every session cookie at once.
    this.secret = randomBytes(KEY_BYTES).toString('base64url')
    this.sessions = []
    this.touched.clear()
    this.save()
    return this.password.updatedAt
  }

  /**
   * Check a candidate password in constant time.
   * @param {string} candidate - what the user typed.
   * @returns whether it matches the stored hash.
   */
  async verifyPassword(candidate) {
    if (this.password === undefined || typeof candidate !== 'string' || candidate === '') return false
    const salt = Buffer.from(this.password.salt, 'base64url')
    const derived = Buffer.from(await scrypt(candidate, salt, 64, SCRYPT))
    const expected = Buffer.from(this.password.hash, 'base64url')
    return derived.length === expected.length && timingSafeEqual(derived, expected)
  }

  /** Remove the permanent password (the caller must have the listener off). */
  clearPassword() {
    this.password = undefined
    this.secret = randomBytes(KEY_BYTES).toString('base64url')
    this.sessions = []
    this.save()
  }

  /** Sign a session cookie value. */
  signSession(id) {
    const signature = createHmac('sha256', this.secret).update(id).digest('base64url')
    return `${id}.${signature}`
  }

  /**
   * Resolve a cookie value to a live session.
   * @param {string | undefined} value - raw cookie value.
   * @returns the session, or undefined for malformed, unknown, expired, or revoked.
   */
  verifySession(value) {
    if (typeof value !== 'string') return undefined
    const separator = value.lastIndexOf('.')
    if (separator <= 0) return undefined
    const id = value.slice(0, separator)
    const presented = value.slice(separator + 1)
    const expected = createHmac('sha256', this.secret).update(id).digest('base64url')
    if (!digestMatches(expected, presented)) return undefined
    const session = this.sessions.find(entry => entry.id === id)
    if (session === undefined || session.revokedAt !== null) return undefined
    if (session.expiresAt <= this.now()) return undefined
    return session
  }

  /**
   * Create one session.
   * @param {{ label?: string, userAgent?: string, address?: string, via?: 'password' | 'invite' }} facts - request facts.
   * @returns the session record plus its cookie value.
   */
  createSession(facts = {}) {
    const now = this.now()
    const session = {
      id: randomUUID(),
      label: typeof facts.label === 'string' && facts.label.trim() !== ''
        ? facts.label.trim().slice(0, 80)
        : describeAgent(facts.userAgent),
      userAgent: typeof facts.userAgent === 'string' ? facts.userAgent.slice(0, 300) : '',
      address: typeof facts.address === 'string' ? facts.address : '',
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + this.sessionDays * 86_400_000,
      revokedAt: null,
      via: facts.via === 'invite' ? 'invite' : 'password',
    }
    this.sessions.push(session)
    if (this.sessions.length > MAX_SESSIONS) {
      this.sessions.sort((a, b) => a.createdAt - b.createdAt)
      this.sessions = this.sessions.slice(this.sessions.length - MAX_SESSIONS)
    }
    this.save()
    return { session, cookie: this.signSession(session.id) }
  }

  /** Refresh activity and slide expiry, coalescing disk writes. */
  touch(id) {
    const session = this.sessions.find(entry => entry.id === id)
    if (session === undefined) return
    const now = this.now()
    const last = this.touched.get(id) ?? 0
    session.lastSeenAt = now
    if (now - last < TOUCH_INTERVAL_MS) return
    this.touched.set(id, now)
    session.expiresAt = now + this.sessionDays * 86_400_000
    this.save()
  }

  /** Sessions without internal secrets, newest first. */
  listSessions() {
    return [...this.sessions]
      .sort((a, b) => b.createdAt - a.createdAt)
      .map(session => ({ ...session }))
  }

  /** Rename one session. */
  renameSession(id, label) {
    const session = this.sessions.find(entry => entry.id === id)
    if (session === undefined) return undefined
    if (typeof label === 'string' && label.trim() !== '') session.label = label.trim().slice(0, 80)
    this.save()
    return { ...session }
  }

  /** Mark one session revoked; its cookie stops authenticating immediately. */
  revokeSession(id) {
    const session = this.sessions.find(entry => entry.id === id)
    if (session === undefined) return undefined
    session.revokedAt = this.now()
    this.save()
    return { ...session }
  }

  /**
   * Forget every session and rotate the signing secret.
   * @returns how many sessions lost access.
   */
  revokeAllSessions() {
    const count = this.sessions.filter(session => session.revokedAt === null).length
    this.sessions = []
    this.invites = []
    this.touched.clear()
    this.secret = randomBytes(KEY_BYTES).toString('base64url')
    this.save()
    return count
  }

  /** Drop expired invite codes. */
  pruneInvites() {
    const now = this.now()
    const before = this.invites.length
    this.invites = this.invites.filter(entry => entry.expiresAt > now)
    return this.invites.length !== before
  }

  /**
   * Mint one single-use invite code.
   * @param {{ ttlMinutes: number, length: number, maxActive: number }} options - code policy.
   * @returns the plaintext code and its expiry.
   */
  createInvite({ ttlMinutes, length, maxActive }) {
    this.pruneInvites()
    while (this.invites.length >= maxActive) this.invites.shift()
    const code = randomCode(length)
    const expiresAt = this.now() + ttlMinutes * 60_000
    this.invites.push({ hash: hashCode(code), createdAt: this.now(), expiresAt })
    this.save()
    return { code, expiresAt }
  }

  /** Withdraw every live invite. */
  cancelInvites() {
    this.invites = []
    this.save()
  }

  /**
   * Redeem one invite for a session. The code is consumed whether or not the
   * session is created, so a replayed code fails.
   * @param {string} code - what the phone typed.
   * @param {{ userAgent?: string, address?: string }} facts - request facts.
   * @returns the session and cookie, or undefined.
   */
  redeemInvite(code, facts = {}) {
    if (typeof code !== 'string') return undefined
    const normalized = code.trim().toUpperCase()
    if (normalized === '') return undefined
    this.pruneInvites()
    const digest = hashCode(normalized)
    const index = this.invites.findIndex(entry => digestMatches(entry.hash, digest))
    if (index === -1) return undefined
    this.invites.splice(index, 1)
    const created = this.createSession({ ...facts, via: 'invite' })
    return created
  }
}
