/**
 * The phone-facing stylesheet, injected as one `style` row.
 *
 * Every rule is scoped to `html[data-rc-mobile="on"]`, an attribute the client
 * half sets from a per-device preference. That keeps the switch honest in both
 * directions: with the attribute absent the document is byte-for-byte the
 * shipped UI, and with it present only the rules below change anything.
 *
 * Deliberate limits: no rule targets a hashed CSS-module class, so an upstream
 * restyle cannot silently reposition things, and nothing here creates or hides
 * structure — that is the slot layer's job.
 */

/** Attribute the client sets while the optimised UI is on. */
export const MOBILE_ATTRIBUTE = 'data-rc-mobile'

/** The attribute selector every rule is scoped by. */
const SCOPE = `html[${MOBILE_ATTRIBUTE}="on"]`

/** Narrow-viewport breakpoint shared with the client half. */
export const NARROW_QUERY = '(max-width: 700px)'

/** Exported so the tests can assert the scoping invariants. */
export const MOBILE_STYLESHEET = `
${SCOPE} {
  -webkit-text-size-adjust: 100%;
  -webkit-tap-highlight-color: transparent;
  /* Replaced with the visual-viewport height by the client half. */
  --rc-vh: 100%;
}

/* The shipped shell sizes itself from height:100%. Pinning #root to the
   visual viewport makes the composer ride above the on-screen keyboard instead
   of hiding behind it — the one phone fix CSS cannot do alone. */
${SCOPE} #root {
  height: var(--rc-vh);
}

/* Pull-to-refresh would reload the page mid-answer; contain the overscroll. */
${SCOPE} body {
  overscroll-behavior-y: none;
}

/* iOS zooms the whole page when a focused field renders below 16px. */
${SCOPE} input,
${SCOPE} textarea,
${SCOPE} select {
  font-size: max(16px, 1em);
}

/* No double-tap zoom and no tap delay on the controls a thumb hits. */
${SCOPE} button,
${SCOPE} [role="button"],
${SCOPE} [role="menuitem"],
${SCOPE} [role="option"],
${SCOPE} a {
  touch-action: manipulation;
}

/* Touch builds: list rows are the main mis-tap source at these sizes. */
@media (pointer: coarse) {
  ${SCOPE} [role="menuitem"],
  ${SCOPE} [role="menuitemcheckbox"],
  ${SCOPE} [role="menuitemradio"],
  ${SCOPE} [role="option"] {
    min-height: 40px;
  }
}

/* Popovers must never extend past the visible area once the keyboard is up. */
${SCOPE} [role="menu"],
${SCOPE} [role="listbox"] {
  max-height: calc(var(--rc-vh) - 24px);
}

/* Wide output scrolls inside itself rather than pushing the page sideways. */
${SCOPE} pre,
${SCOPE} table,
${SCOPE} .md-code-block {
  max-width: 100%;
}
`.trim()

/**
 * Runs before first paint so the optimised UI never flashes the desktop layout
 * on a phone. Kept as a string because it is injected into the document head.
 */
export const MOBILE_BOOT_SCRIPT = `(() => {
  try {
    const pref = localStorage.getItem('dsh-rc.mobile-ui') || 'auto'
    const narrow = window.matchMedia('${NARROW_QUERY}').matches
    if (pref === 'on' || (pref === 'auto' && narrow)) {
      document.documentElement.setAttribute('${MOBILE_ATTRIBUTE}', 'on')
    }
  } catch (error) {
    // Private mode or blocked storage: fall through to the desktop UI.
  }
})()`
