/**
 * The phone-facing layer's two invariants:
 *
 * 1. Every rule is scoped to the attribute the client half sets, so switching
 *    the optimised UI off really does restore the shipped stylesheet.
 * 2. The pre-paint script picks the same mode the client half would, for every
 *    stored preference, and never throws when storage is blocked.
 */

import assert from 'node:assert/strict'
import vm from 'node:vm'
import { describe, it } from 'node:test'

import { MOBILE_ATTRIBUTE, MOBILE_BOOT_SCRIPT, MOBILE_STYLESHEET, NARROW_QUERY } from '../lib/mobile-css.js'

const SCOPE = `html[${MOBILE_ATTRIBUTE}="on"]`

/**
 * Collector for the selector text of every block in a stylesheet.
 * A block opens at `{`; its selector is the text since the previous brace.
 * @param {string} css - the stylesheet text.
 * @returns {string[]} selector text per block, at-rule openers included.
 */
function blockSelectors(css) {
  const selectors = []
  // Comments may contain braces-free prose; drop them so they cannot prefix a
  // selector and hide an unscoped rule.
  const source = css.replace(/\/\*[\s\S]*?\*\//gu, '')
  let buffer = ''
  for (const character of source) {
    if (character === '{') {
      selectors.push(buffer.trim())
      buffer = ''
      continue
    }
    if (character === '}') {
      buffer = ''
      continue
    }
    buffer += character
  }
  return selectors
}

describe('mobile stylesheet scoping', () => {
  it('scopes every declaration block to the switch attribute', () => {
    const selectors = blockSelectors(MOBILE_STYLESHEET).filter(selector => selector !== '')
    assert.ok(selectors.length >= 8, `expected several blocks, saw ${selectors.length}`)
    for (const selector of selectors) {
      if (selector.startsWith('@')) continue
      assert.ok(
        selector.includes(SCOPE),
        `unscoped rule would leak into the desktop UI: ${JSON.stringify(selector.slice(0, 80))}`,
      )
    }
  })

  it('contains no at-rule that escapes the scope', () => {
    for (const selector of blockSelectors(MOBILE_STYLESHEET)) {
      if (!selector.startsWith('@')) continue
      assert.match(selector, /^@media|^@supports/u)
    }
  })

  it('scopes every hash-based selector inside the transcript', () => {
    // Class names are CSS-module hashes: matching them is allowed only inside
    // the chat flow, where a stale hash degrades one bubble instead of
    // repositioning unrelated chrome.
    const hashRules = MOBILE_STYLESHEET.split('}').filter(block => block.includes('[class*='))
    assert.ok(hashRules.length >= 1, 'the bubble rule should exist')
    for (const block of hashRules) {
      assert.match(block, /\[data-chat-flow\]/u, `hash match outside the transcript: ${block.trim().slice(0, 80)}`)
    }
  })

  it('makes the transcript full-bleed through the documented hooks', () => {
    assert.match(MOBILE_STYLESHEET, /\[data-chat-flow\][^}]*max-width:\s*100%/u)
    assert.match(MOBILE_STYLESHEET, /--dsh-chat-content-width:\s*100%/u)
    assert.match(MOBILE_STYLESHEET, /:has\(> \[data-chat-flow\]\)/u)
    // The editor cap keeps a long draft from eating the screen.
    assert.match(MOBILE_STYLESHEET, /\[data-phase\][^}]*max-height/u)
  })

  it('keys the keyboard fix off the visual-viewport variable', () => {
    assert.match(MOBILE_STYLESHEET, /#root\s*\{[^}]*height:\s*var\(--rc-vh\)/u)
  })

  it('never closes its own script element', () => {
    assert.equal(MOBILE_BOOT_SCRIPT.includes('</script'), false)
    assert.equal(MOBILE_STYLESHEET.includes('</style'), false)
  })
})

describe('pre-paint switch script', () => {
  /** Run the boot script against stubs and report the attribute it set. */
  function run({ preference, narrow, blocked = false }) {
    const attributes = new Map()
    const context = {
      window: { matchMedia: () => ({ matches: narrow }) },
      localStorage: {
        getItem: () => {
          if (blocked) throw new Error('storage blocked')
          return preference
        },
      },
      document: {
        documentElement: {
          setAttribute: (name, value) => attributes.set(name, value),
        },
      },
    }
    vm.runInNewContext(MOBILE_BOOT_SCRIPT, context)
    return attributes.get(MOBILE_ATTRIBUTE)
  }

  it('turns the optimised UI on for an explicit on, at any width', () => {
    assert.equal(run({ preference: 'on', narrow: false }), 'on')
    assert.equal(run({ preference: 'on', narrow: true }), 'on')
  })

  it('follows the viewport for auto', () => {
    assert.equal(run({ preference: 'auto', narrow: true }), 'on')
    assert.equal(run({ preference: 'auto', narrow: false }), undefined)
  })

  it('leaves the shipped UI alone for off, and for an unset preference at width', () => {
    assert.equal(run({ preference: 'off', narrow: true }), undefined)
    assert.equal(run({ preference: null, narrow: false }), undefined)
    assert.equal(run({ preference: 'garbage', narrow: false }), undefined)
  })

  it('survives blocked storage without touching the document', () => {
    assert.equal(run({ preference: 'on', narrow: true, blocked: true }), undefined)
  })

  it('uses the same breakpoint the client half does', () => {
    assert.equal(NARROW_QUERY, '(max-width: 700px)')
    assert.match(MOBILE_BOOT_SCRIPT, /max-width: 700px/u)
  })
})
