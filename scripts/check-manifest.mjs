/**
 * Repository-level consistency checks, run by CI and before every publish.
 *
 * The package name appears in three places that must agree: the manifest, the
 * bundle patch row the Loader resolves, and the browser module id the shell
 * hands to its module loader. A rename that misses one of them installs a
 * plugin that never loads — cheap to check, expensive to discover on a phone.
 *
 * No dependencies: plain Node so CI needs no install step.
 */

import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const failures = []

/** Read one file relative to the package root. */
function read(name) {
  return readFileSync(join(root, name), 'utf8')
}

/** Record a failure instead of throwing, so one run reports every problem. */
function check(condition, message) {
  if (!condition) failures.push(message)
}

const manifest = JSON.parse(read('package.json'))
const name = manifest.name
const version = manifest.version

// ── name must agree in all three places ────────────────────────────────────
const patchName = /^\s*name:\s*'([^']+)'/mu.exec(read('cordis.patch.yml'))?.[1]
const clientId = /id:\s*'([^']+)'/u.exec(read('client.js'))?.[1]
check(patchName === name, `cordis.patch.yml row name ${JSON.stringify(patchName)} != package.json ${JSON.stringify(name)}`)
check(clientId === name, `client.js module id ${JSON.stringify(clientId)} != package.json ${JSON.stringify(name)}`)

// ── version shape ──────────────────────────────────────────────────────────
check(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(version ?? ''), `package.json version ${JSON.stringify(version)} is not semver`)

// ── runtime files exist and are published ──────────────────────────────────
const required = [
  'index.js',
  'client.js',
  'cordis.patch.yml',
  'icon.svg',
  'locale/en.json',
  'locale/zh.json',
  'README.md',
  'LICENSE',
  'lib/addresses.js',
  'lib/gate.js',
  'lib/listener.js',
  'lib/proxy.js',
  'lib/state.js',
  'lib/tunnel.js',
  'lib/upstream.js',
]
for (const file of required) check(existsSync(join(root, file)), `missing required file ${file}`)

const published = new Set(manifest.files ?? [])
for (const entry of ['index.js', 'client.js', 'cordis.patch.yml', 'icon.svg', 'lib/*.js', 'locale/*.json', 'README.md', 'LICENSE']) {
  check(published.has(entry), `package.json "files" is missing ${JSON.stringify(entry)}`)
}

// ── publishability ─────────────────────────────────────────────────────────
const args = process.argv.slice(2)
const publishing = args.includes('--publish')
if (publishing) {
  check(manifest.private !== true, 'package.json "private": true blocks publishing')
  check(!String(name).startsWith('@local/'), `package name ${JSON.stringify(name)} uses the @local scope, which cannot be published`)
  check(manifest.publishConfig?.access === 'public', 'package.json publishConfig.access must be "public"')
}

// ── optional: the pushed tag must match the manifest version ───────────────
const tagIndex = args.indexOf('--tag')
if (tagIndex !== -1) {
  const tag = args[tagIndex + 1] ?? ''
  check(tag === `v${version}`, `tag ${JSON.stringify(tag)} does not match package.json version ${JSON.stringify(version)} (expected "v${version}")`)
}

if (failures.length > 0) {
  console.error('check-manifest: FAILED')
  for (const failure of failures) console.error(`  - ${failure}`)
  process.exit(1)
}

console.log(`check-manifest: OK  ${name}@${version}`)
