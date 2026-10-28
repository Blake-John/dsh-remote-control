/**
 * A bounded, best-effort record of what happens to each entry socket.
 *
 * The phone reports "connection lost" and "can't establish a connection"
 * without a reason, and both the entry listener and the Harness sit on this
 * machine: the only way to tell a gate rejection from an upstream that closed
 * the tunnel is to keep the sequence on disk. Every write is best-effort —
 * a diagnostic that can throw would turn a healthy request into a failure.
 */

import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** Lines kept before the file is halved; small enough to read in one pass. */
const MAX_LINES = 400

/**
 * Collects socket-lifecycle facts for one entry listener.
 */
export class Diagnostics {
  /**
   * @param {{path: string, enabled?: boolean, now?: () => number}} options - destination and switch.
   */
  constructor({ path, enabled = true, now = Date.now }) {
    this.path = path
    this.enabled = enabled
    this.now = now
    /** @type {number} */
    this.lines = 0
    /** @type {string | undefined} */
    this.error = undefined
    if (this.enabled) this.#count()
  }

  /** Count the lines already on disk so a restart does not grow the file forever. */
  #count() {
    try {
      mkdirSync(dirname(this.path), { recursive: true })
      this.lines = readFileSync(this.path, 'utf8').split('\n').filter(Boolean).length
    } catch {
      this.lines = 0
    }
  }

  /**
   * Append one event. Never throws.
   * @param {string} event - short, stable name such as `upgrade` or `upstream-close`.
   * @param {Record<string, unknown>} [fields] - extra facts for this event.
   */
  record(event, fields = {}) {
    if (!this.enabled) return
    const line = JSON.stringify({ t: new Date(this.now()).toISOString(), event, ...fields })
    try {
      if (this.lines >= MAX_LINES) this.#rotate()
      appendFileSync(this.path, `${line}\n`)
      this.lines += 1
      this.error = undefined
    } catch (error) {
      // Report once, then stay quiet: a full disk must not repeat on every socket.
      if (this.error === undefined) {
        this.error = error instanceof Error ? error.message : String(error)
      }
    }
  }

  /** Keep the newest half of the file, so rotation costs one rewrite per MAX_LINES/2 events. */
  #rotate() {
    const kept = readFileSync(this.path, 'utf8').split('\n').filter(Boolean).slice(-Math.floor(MAX_LINES / 2))
    const temporary = `${this.path}.tmp`
    writeFileSync(temporary, kept.length === 0 ? '' : `${kept.join('\n')}\n`)
    renameSync(temporary, this.path)
    this.lines = kept.length
  }

  /** What the settings page shows. */
  info() {
    return { enabled: this.enabled, path: this.path, lines: this.lines, error: this.error }
  }
}
