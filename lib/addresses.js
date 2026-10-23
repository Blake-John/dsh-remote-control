/**
 * Local interface addresses: classification, URL spelling, and the set the
 * settings page may offer as a bind target.
 *
 * Classification is presentation only (which network the user probably
 * reached); the permission decision is always the explicit configuration.
 */

import { networkInterfaces } from 'node:os'

/** True for any IPv4/IPv6 loopback spelling. */
export function isLoopbackAddress(address) {
  return address === '::1'
    || address === '0:0:0:0:0:0:0:1'
    || /^127\./u.test(address)
    || /^::ffff:127\./iu.test(address)
}

/**
 * Classify one interface address.
 * @param {string} address - dotted-quad or IPv6 text.
 * @param {string} ifaceName - owning interface name, used as a hint.
 * @returns {'loopback' | 'tailscale' | 'private' | 'link-local' | 'public'}
 */
export function classifyAddress(address, ifaceName = '') {
  if (isLoopbackAddress(address)) return 'loopback'
  const hint = String(ifaceName).toLowerCase()
  if (/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./u.test(address)) return 'tailscale'
  if (address.toLowerCase().startsWith('fd7a:115c:a1e0:')) return 'tailscale'
  if (/tailscale|tsnet/u.test(hint)) return 'tailscale'
  if (/zerotier|^zt[a-z0-9]*$/u.test(hint)) return 'private'
  if (/^fe80:/iu.test(address)) return 'link-local'
  if (/^f[cd][0-9a-f]{2}:/iu.test(address)) return 'private'
  if (/^10\./u.test(address)) return 'private'
  if (/^192\.168\./u.test(address)) return 'private'
  const dotted = /^172\.(\d{1,3})\./u.exec(address)
  if (dotted !== null) {
    const second = Number(dotted[1])
    if (second >= 16 && second <= 31) return 'private'
  }
  return 'public'
}

/**
 * Render one URL host the way `node:http` and WHATWG both read it.
 * @param {string} address - bare address text.
 * @returns bracketed IPv6 or plain IPv4, or undefined for a zoned address.
 */
export function urlHost(address) {
  if (address.includes('%')) return undefined
  return address.includes(':') ? `[${address}]` : address
}

/** Build `protocol//host:port/` for an address; undefined when unspellable. */
export function originFor(protocol, address, port) {
  const host = urlHost(address)
  if (host === undefined) return undefined
  return `${protocol}//${host}:${port}/`
}

/** True for an address that would bind every interface. */
export function isWildcardAddress(address) {
  return address === '' || address === '0.0.0.0' || address === '::' || address === '[::]'
}

/** Whether an address may be bound as the remote entry. */
export function isBindable(address) {
  return urlHost(address) !== undefined && !isLoopbackAddress(address) && classifyAddress(address) !== 'link-local'
}

/**
 * Every local address with the facts the settings page needs.
 * @param {number} port - port the entry would listen on, used for the URL.
 * @param {string} [protocol] - `http:` (the entry listener is plain HTTP in v2).
 * @returns {Array<{address: string, family: string, iface: string, internal: boolean, kind: string, bindable: boolean, recommended: boolean, url: string | undefined}>}
 */
export function listAddresses(port, protocol = 'http:') {
  const seen = new Map()
  for (const [ifaceName, entries] of Object.entries(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (seen.has(entry.address)) continue
      const family = String(entry.family).includes('6') ? 'IPv6' : 'IPv4'
      const kind = classifyAddress(entry.address, ifaceName ?? '')
      seen.set(entry.address, {
        address: entry.address,
        family,
        iface: ifaceName ?? '',
        internal: entry.internal === true,
        kind,
        bindable: isBindable(entry.address),
        recommended: kind === 'tailscale' || (kind === 'private' && !entry.internal),
        url: originFor(protocol, entry.address, port),
      })
    }
  }
  return [...seen.values()].sort((a, b) => {
    const rank = { tailscale: 0, private: 1, public: 2, loopback: 3, 'link-local': 4 }
    return (rank[a.kind] ?? 5) - (rank[b.kind] ?? 5) || a.address.localeCompare(b.address)
  })
}

/**
 * Parse a CIDR block (`100.64.0.0/10`, `fd00::/8`) or a bare address.
 * @param {string} text - configured allow entry.
 * @returns {{family: 4 | 6, bytes: Uint8Array, prefix: number} | undefined}
 */
export function parseCidr(text) {
  if (typeof text !== 'string' || text.trim() === '') return undefined
  const [address, prefixText] = text.trim().split('/')
  const family = address.includes(':') ? 6 : 4
  const bytes = family === 4 ? parseIpv4(address) : parseIpv6(address)
  if (bytes === undefined) return undefined
  const max = family === 4 ? 32 : 128
  const prefix = prefixText === undefined ? max : Number(prefixText)
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) return undefined
  return { family, bytes, prefix }
}

/** Whether `address` falls inside the parsed CIDR. */
export function inCidr(cidr, address) {
  const normalized = normalizeMapped(String(address))
  const family = normalized.includes(':') ? 6 : 4
  if (cidr.family !== family) return false
  const bytes = family === 4 ? parseIpv4(normalized) : parseIpv6(normalized)
  if (bytes === undefined) return false
  let remaining = cidr.prefix
  for (let index = 0; index < bytes.length; index += 1) {
    if (remaining <= 0) return true
    const bits = Math.min(8, remaining)
    const mask = bits === 8 ? 0xff : (0xff << (8 - bits)) & 0xff
    if ((bytes[index] & mask) !== (cidr.bytes[index] & mask)) return false
    remaining -= bits
  }
  return true
}

/** Whether an address passes the configured allow list; an empty list allows all. */
export function allowsAddress(allowFrom, address) {
  if (!Array.isArray(allowFrom) || allowFrom.length === 0) return true
  const parsed = allowFrom.map(parseCidr).filter(entry => entry !== undefined)
  if (parsed.length === 0) return true
  return parsed.some(cidr => inCidr(cidr, address))
}

/** Strip an IPv4-mapped IPv6 prefix so one address compares one way. */
function normalizeMapped(address) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/iu.exec(address)
  return mapped === null ? address : mapped[1]
}

/** Dotted quad to bytes. */
function parseIpv4(address) {
  const parts = address.split('.')
  if (parts.length !== 4) return undefined
  const bytes = new Uint8Array(4)
  for (let index = 0; index < 4; index += 1) {
    const value = Number(parts[index])
    if (!/^\d{1,3}$/u.test(parts[index]) || value > 255) return undefined
    bytes[index] = value
  }
  return bytes
}

/** IPv6 text (with `::` compression) to bytes. */
function parseIpv6(address) {
  const text = address.split('%')[0].toLowerCase()
  if (text === '') return undefined
  const halves = text.split('::')
  if (halves.length > 2) return undefined
  const head = halves[0] === '' ? [] : halves[0].split(':')
  const tail = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : []
  const groups = []
  // A trailing dotted quad counts as two groups.
  const expand = (parts) => {
    const out = []
    for (const part of parts) {
      if (part.includes('.')) {
        const quad = parseIpv4(part)
        if (quad === undefined) return undefined
        out.push((quad[0] << 8) | quad[1], (quad[2] << 8) | quad[3])
        continue
      }
      if (!/^[0-9a-f]{1,4}$/u.test(part)) return undefined
      out.push(Number.parseInt(part, 16))
    }
    return out
  }
  const headGroups = expand(head)
  const tailGroups = expand(tail)
  if (headGroups === undefined || tailGroups === undefined) return undefined
  const missing = 8 - headGroups.length - tailGroups.length
  if (halves.length === 2) {
    if (missing < 0) return undefined
    groups.push(...headGroups, ...new Array(missing).fill(0), ...tailGroups)
  } else {
    if (headGroups.length !== 8) return undefined
    groups.push(...headGroups)
  }
  const bytes = new Uint8Array(16)
  groups.forEach((group, index) => {
    bytes[index * 2] = (group >> 8) & 0xff
    bytes[index * 2 + 1] = group & 0xff
  })
  return bytes
}
