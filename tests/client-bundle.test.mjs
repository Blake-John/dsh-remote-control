/**
 * Guards for the browser half.
 *
 * The bundle is a single classic script handed to the shell's module loader, so
 * a Node test cannot mount it. What it can do is check the two properties whose
 * loss produced a blank settings panel: the entry form is never cleared to
 * `undefined` between an action and its reload, and the slot entry keeps its
 * render-time safety net. Both are source-level facts, so they are asserted
 * against the shipped file.
 */

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it } from 'node:test'

const root = join(import.meta.dirname, '..')
const source = readFileSync(join(root, 'client.js'), 'utf8')
/** The manifest name is the module id, so a rename never needs a test edit. */
const packageName = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).name

describe('client bundle integrity', () => {
  it('parses as a classic script that registers one module factory', () => {
    // `new Function` throws on a syntax error without needing a browser.
    assert.doesNotThrow(() => new Function(source))
    assert.match(source, /window\.__ModuleLoader__\.load\(\{/u)
    // The shell keys the browser module by the package name; a mismatch means
    // the settings page silently never loads.
    assert.ok(
      source.includes(`id: '${packageName}'`),
      `client.js module id must equal the package name ${JSON.stringify(packageName)}`,
    )
  })

  it('never clears the entry form between an action and its reload', () => {
    // The crash: setForm(undefined) left one render with `status` present and
    // `form` missing, which threw inside the field renderers and blanked the
    // panel. The form is now rebuilt from the fresh status instead.
    assert.doesNotMatch(source, /setForm\(undefined\)/u)
    assert.match(source, /load\(true\)/u)
    assert.match(source, /function formFromStatus\(status\)/u)
  })

  it('refuses to render the fields without a form', () => {
    assert.match(source, /status === undefined \|\| form === undefined/u)
  })

  it('wraps the section in a render-time boundary', () => {
    assert.match(source, /class SectionBoundary extends React\.Component/u)
    assert.match(source, /static getDerivedStateFromError/u)
    assert.match(source, /\}, RemoteControlShell\)\)/u)
  })

  it('registers the settings section under its own slot id', () => {
    assert.match(source, /name: 'settings\.section'/u)
    assert.match(source, /id: 'remote-control'/u)
    assert.match(source, /inject: \['slots', 'locale', 'connection'\]/u)
  })

  it('translates every key it looks up', () => {
    const used = new Set()
    for (const match of source.matchAll(/\bt\('([a-zA-Z]+)'\)/gu)) used.add(match[1])
    // Keys reached through `fill(t('…'))` and the kind table are literal too.
    for (const key of used) {
      const occurrences = source.split(`      ${key}: `).length - 1
      assert.ok(occurrences >= 2, `locale key "${key}" must exist in both dictionaries (found ${occurrences})`)
    }
  })
})
