/**
 * dsh-remote-control — the browser half.
 *
 * One Settings → Remote Control page owns the whole remote surface: pick the
 * address the phone will reach (a Tailscale or LAN address of this machine),
 * set the permanent password, mint a one-time invite, and revoke devices. The
 * page also re-opens the connection when a phone returns to the foreground,
 * which is the one transport fix a browser cannot get from the Host.
 */
window.__ModuleLoader__.load({
  id: 'dsh-remote-control',
  factory(require) {
    const React = require('react')
    const h = React.createElement
    const NS = 'remoteControl'

    const zh = {
      nav: '远程控制',
      title: '远程控制',
      subtitle: '给手机开一个入口：本插件只负责暴露与登录，隧道与内网穿透不在范围内。',
      refresh: '刷新',
      loadFailed: '读取状态失败：{reason}',
      upstreamOk: '上游 Harness：{authority}',
      upstreamBad: '无法确认上游 Harness 地址：{reason}',
      credentialReady: '服务端凭据已就绪',
      credentialFailed: '服务端凭据获取失败：{reason}',
      credentialIdle: '服务端凭据：尚未使用',
      entry: '入口',
      entryOn: '入口已开启',
      entryOff: '入口已关闭',
      entryError: '入口启动失败：{reason}',
      entryUrl: '手机访问地址',
      hostLabel: '监听地址',
      hostHint: '选择手机能路由到的本机地址：Tailscale 用 100.64/10 段，局域网用私网段。回环地址不能作为入口。',
      hostEmpty: '这个端口下没有可绑定的网络地址，请检查网卡或 Tailscale 状态。',
      hostMissing: '当前保存的地址 {address} 现在不在本机网卡上（Tailscale 掉线或地址变了），请重新选择。',
      portLabel: '端口',
      allowLabel: '来源白名单（可选，逗号分隔 CIDR）',
      allowHint: '留空表示不限制来源；例如只允许 tailnet：100.64.0.0/10',
      enableLabel: '开启入口',
      apply: '应用',
      applying: '应用中…',
      applied: '已应用',
      kindTailscale: 'Tailscale',
      kindPrivate: '内网',
      kindPublic: '公网',
      kindLoopback: '回环',
      kindLinkLocal: '链路本地',
      password: '永久密码',
      passwordSet: '已设置（更新于 {when}）',
      passwordMissing: '尚未设置：开启入口前必须先设密码，或先生成邀请码。',
      passwordCurrent: '当前密码',
      passwordNext: '新密码',
      passwordConfirm: '确认新密码',
      passwordSave: '保存密码',
      passwordMismatch: '两次输入的新密码不一致。',
      passwordTooShort: '至少 8 个字符。',
      passwordSaved: '密码已保存，所有已登录设备已被强制下线。',
      passwordClear: '清除密码',
      minLength: '至少 {n} 个字符',
      invite: '一次性邀请',
      inviteHint: '生成一个只能用一次的码，交给临时使用的人；它不需要密码，过期或使用后失效。',
      inviteCreate: '生成邀请码',
      inviteCancel: '取消邀请',
      inviteActive: '有 {n} 个有效邀请',
      inviteCode: '邀请码（{minutes} 分钟后失效）',
      sessions: '已登录设备',
      sessionEmpty: '还没有设备登录过。',
      sessionRevoke: '下线',
      sessionRename: '重命名',
      sessionAll: '全部下线',
      sessionAllConfirm: '让所有设备重新输入密码？',
      sessionName: '设备名称',
      sessionCreated: '登录于',
      sessionSeen: '最近活跃',
      sessionVia: '方式：密码',
      sessionViaInvite: '方式：邀请码',
      sessionExpires: '会话有效期：{days} 天（滑动续期）',
      never: '从未',
      diagnostics: '诊断',
      diagLine: '监听 {state} · 白名单 {allow} · 会话 {days} 天 · 邀请 {ttl} 分钟',
      allowNone: '无限制',
      securityTitle: '安全边界',
      securityBody: '入口是明文 HTTP，靠 tailnet / 局域网本身加密；密码等同于本机权限，请用长密码。本插件不进隧道、不开通公网端口，也不按请求头转发到别处——目标永远是本机回环上的 Harness。',
      transportTitle: '移动端优化',
      transportBody: '窄屏字号、安全区与触摸目标由本插件注入；页面回到前台会主动重连，避免手机休眠后长时间空白。',
      on: '开',
      off: '关',
      yes: '是',
      no: '否',
      copy: '复制',
      copied: '已复制',
      open: '打开',
      crashed: '这个面板渲染失败',
      crashedHint: '刷新页面可重试；若持续出现，请把浏览器控制台的报错贴出来。',
    }

    const en = {
      nav: 'Remote Control',
      title: 'Remote Control',
      subtitle: 'Give a phone an entry point. This plugin exposes and authenticates only; tunnels and NAT traversal stay out of scope.',
      refresh: 'Refresh',
      loadFailed: 'Could not read the status: {reason}',
      upstreamOk: 'Upstream Harness: {authority}',
      upstreamBad: 'Cannot resolve the upstream Harness address: {reason}',
      credentialReady: 'Server-side credential is ready',
      credentialFailed: 'Server-side credential failed: {reason}',
      credentialIdle: 'Server-side credential: not used yet',
      entry: 'Entry',
      entryOn: 'Entry is on',
      entryOff: 'Entry is off',
      entryError: 'Entry failed to start: {reason}',
      entryUrl: 'Address to open on the phone',
      hostLabel: 'Listen address',
      hostHint: 'Pick a local address the phone can route to: 100.64/10 for Tailscale, a private range for the LAN. Loopback cannot be the entry.',
      hostEmpty: 'No bindable network address at this port. Check the interfaces or Tailscale state.',
      hostMissing: 'The saved address {address} is no longer on this machine (Tailscale down or the address changed); pick another one.',
      portLabel: 'Port',
      allowLabel: 'Source allow list (optional, comma-separated CIDR)',
      allowHint: 'Empty means no restriction; for example 100.64.0.0/10 to allow the tailnet only.',
      enableLabel: 'Enable the entry',
      apply: 'Apply',
      applying: 'Applying…',
      applied: 'Applied',
      kindTailscale: 'Tailscale',
      kindPrivate: 'private',
      kindPublic: 'public',
      kindLoopback: 'loopback',
      kindLinkLocal: 'link-local',
      password: 'Permanent password',
      passwordSet: 'Set (updated {when})',
      passwordMissing: 'Not set yet: set a password, or mint an invite, before opening the entry.',
      passwordCurrent: 'Current password',
      passwordNext: 'New password',
      passwordConfirm: 'Confirm new password',
      passwordSave: 'Save password',
      passwordMismatch: 'The two new passwords do not match.',
      passwordTooShort: 'Use at least 8 characters.',
      passwordSaved: 'Password saved; every signed-in device was signed out.',
      passwordClear: 'Clear password',
      minLength: 'at least {n} characters',
      invite: 'One-time invite',
      inviteHint: 'Mint a single-use code for someone who needs a quick look. It needs no password and dies on use or expiry.',
      inviteCreate: 'Mint invite',
      inviteCancel: 'Cancel invites',
      inviteActive: '{n} live invite(s)',
      inviteCode: 'Invite code (expires in {minutes} min)',
      sessions: 'Signed-in devices',
      sessionEmpty: 'No device has signed in yet.',
      sessionRevoke: 'Sign out',
      sessionRename: 'Rename',
      sessionAll: 'Sign out every device',
      sessionAllConfirm: 'Force every device to type the password again?',
      sessionName: 'Device name',
      sessionCreated: 'signed in',
      sessionSeen: 'last seen',
      sessionVia: 'via password',
      sessionViaInvite: 'via invite',
      sessionExpires: 'Session lifetime: {days} days, sliding',
      never: 'never',
      diagnostics: 'Diagnostics',
      diagLine: 'listener {state} · allow list {allow} · sessions {days}d · invites {ttl}m',
      allowNone: 'unrestricted',
      securityTitle: 'Security boundary',
      securityBody: 'The entry speaks plain HTTP and relies on the tailnet or LAN for encryption; the password equals local authority, so make it long. This plugin opens no tunnel and never forwards by request header: the target is always the Harness on this machine.',
      transportTitle: 'Mobile transport',
      transportBody: 'Narrow-screen type, safe-area padding and touch targets are injected by this plugin, and the page reconnects when it returns to the foreground so a sleeping phone does not stare at a blank shell.',
      on: 'on',
      off: 'off',
      yes: 'yes',
      no: 'no',
      copy: 'Copy',
      copied: 'Copied',
      open: 'Open',
      crashed: 'This panel failed to render',
      crashedHint: 'Reload the page to retry; paste the browser console error if it keeps happening.',
    }

    const S = {
      page: { display: 'flex', flexDirection: 'column', gap: 16, padding: '4px 0 24px', fontFamily: 'inherit' },
      card: {
        background: 'var(--dsw-alias-bg-layer-1)',
        border: '1px solid var(--dsw-alias-border-l1)',
        borderRadius: 12,
        padding: 16,
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
      },
      h2: { margin: 0, fontSize: 15, fontWeight: 600, color: 'var(--dsw-alias-label-primary)' },
      muted: { margin: 0, fontSize: 13, lineHeight: 1.5, color: 'var(--dsw-alias-label-secondary)' },
      mono: { fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12, wordBreak: 'break-all' },
      row: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
      between: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' },
      label: { fontSize: 12, color: 'var(--dsw-alias-label-secondary)' },
      input: {
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-label-primary)',
        border: '1px solid var(--dsw-alias-border-l2)',
        borderRadius: 8,
        padding: '8px 10px',
        fontSize: 13,
        minHeight: 36,
        minWidth: 0,
      },
      button: {
        appearance: 'none',
        border: '1px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-layer-2)',
        color: 'var(--dsw-alias-label-primary)',
        borderRadius: 8,
        padding: '8px 12px',
        fontSize: 13,
        cursor: 'pointer',
        minHeight: 36,
      },
      primary: {
        appearance: 'none',
        border: '1px solid var(--dsw-alias-brand-primary)',
        background: 'var(--dsw-alias-brand-primary)',
        color: '#fff',
        borderRadius: 8,
        padding: '9px 14px',
        fontSize: 13,
        fontWeight: 600,
        cursor: 'pointer',
        minHeight: 36,
      },
      chip: {
        fontSize: 11,
        padding: '2px 8px',
        borderRadius: 999,
        border: '1px solid var(--dsw-alias-border-l1)',
        color: 'var(--dsw-alias-label-secondary)',
        whiteSpace: 'nowrap',
      },
      list: { display: 'flex', flexDirection: 'column', gap: 8 },
      item: {
        display: 'flex',
        flexDirection: 'column',
        gap: 6,
        padding: '10px 12px',
        borderRadius: 8,
        background: 'var(--dsw-alias-bg-layer-2)',
        border: '1px solid var(--dsw-alias-border-l1)',
      },
      code: {
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: 24,
        letterSpacing: 6,
        fontWeight: 700,
        color: 'var(--dsw-alias-label-primary)',
      },
      error: { margin: 0, fontSize: 12, color: 'var(--dsw-alias-state-error-primary)' },
      warn: { margin: 0, fontSize: 12, color: 'var(--dsw-alias-state-warn-primary)' },
      ok: { margin: 0, fontSize: 12, color: 'var(--dsw-alias-state-success-primary)' },
    }

    /** Substitute `{name}` placeholders. */
    function fill(template, values) {
      return String(template).replace(/\{(\w+)\}/gu, (_match, key) => String(values[key] ?? ''))
    }

    /** Short relative time from an epoch millisecond value. */
    function ago(t, value) {
      if (typeof value !== 'number' || value <= 0) return t('never')
      const seconds = Math.max(0, Math.round((Date.now() - value) / 1000))
      if (seconds < 60) return `${seconds}s`
      if (seconds < 3600) return `${Math.round(seconds / 60)}m`
      if (seconds < 86_400) return `${Math.round(seconds / 3600)}h`
      return `${Math.round(seconds / 86_400)}d`
    }

    /**
     * The editable entry form for one status document. Kept as a pure function
     * so every reload (and every successful action) rebuilds it the same way.
     * @param {object} status - the `status` RPC value.
     * @returns {{enabled: boolean, host: string, port: string, allowFrom: string}}
     */
    function formFromStatus(status) {
      return {
        enabled: status.listener.enabled,
        host: status.listener.host === ''
          ? (status.addresses.find(entry => entry.bindable)?.address ?? '')
          : status.listener.host,
        port: String(status.listener.port),
        allowFrom: status.listener.allowFrom.join(', '),
      }
    }

    /** Kind label for one address row. */
    function kindLabel(t, kind) {
      if (kind === 'tailscale') return t('kindTailscale')
      if (kind === 'private') return t('kindPrivate')
      if (kind === 'public') return t('kindPublic')
      if (kind === 'loopback') return t('kindLoopback')
      return t('kindLinkLocal')
    }

    /** One copy button that reports success inline. */
    function CopyButton({ t, value }) {
      const [copied, setCopied] = React.useState(false)
      return h('button', {
        type: 'button',
        style: S.button,
        onClick: () => {
          const clipboard = navigator.clipboard
          if (clipboard === undefined) return
          clipboard.writeText(value).then(() => {
            setCopied(true)
            setTimeout(() => setCopied(false), 1200)
          }).catch(() => {})
        },
      }, copied ? t('copied') : t('copy'))
    }

    /** The Remote Control settings page. */
    function RemoteControlSection(props) {
      const t = props.t
      const call = props.call
      const [status, setStatus] = React.useState(undefined)
      const [error, setError] = React.useState(undefined)
      const [busy, setBusy] = React.useState(false)
      const [notice, setNotice] = React.useState(undefined)
      const [invite, setInvite] = React.useState(undefined)
      const [now, setNow] = React.useState(Date.now())
      const [form, setForm] = React.useState(undefined)
      const [passwordForm, setPasswordForm] = React.useState({ current: '', next: '', confirm: '' })

      /**
       * Read the status document.
       * @param {boolean} [sync] - rebuild the editable form from the answer; a
       * successful action passes true, a background poll leaves user edits alone.
       */
      const load = React.useCallback((sync = false) => {
        let live = true
        call('status').then((value) => {
          if (!live) return
          setStatus(value)
          setError(undefined)
          setForm((previous) => (sync || previous === undefined) ? formFromStatus(value) : previous)
        }).catch((reason) => {
          if (live) setError(reason instanceof Error ? reason.message : String(reason))
        })
        return () => { live = false }
      }, [call])

      React.useEffect(() => load(), [load])
      React.useEffect(() => {
        const timer = setInterval(() => load(), 15_000)
        return () => clearInterval(timer)
      }, [load])
      React.useEffect(() => {
        const timer = setInterval(() => setNow(Date.now()), 1000)
        return () => clearInterval(timer)
      }, [])

      const run = (method, args, after) => {
        setBusy(true)
        setNotice(undefined)
        return call(method, args).then((value) => {
          if (after !== undefined) after(value)
          // Reload *with* a form rebuild: clearing the form first left one
          // render with `status` set and `form` undefined, which crashed the
          // section and blanked the panel.
          load(true)
          return value
        }).catch((reason) => {
          setNotice(reason instanceof Error ? reason.message : String(reason))
        }).finally(() => setBusy(false))
      }

      if (status === undefined || form === undefined) {
        return h('div', { style: S.page },
          h('p', { style: S.muted }, error === undefined ? t('refresh') : fill(t('loadFailed'), { reason: error })))
      }

      const applyEntry = () => {
        run('listener/apply', {
          enabled: form.enabled,
          host: form.host,
          port: Number(form.port),
          allowFrom: form.allowFrom.split(',').map(part => part.trim()).filter(part => part !== ''),
        }, () => setNotice(t('applied')))
      }

      const savePassword = () => {
        if (passwordForm.next.length < status.limits.minPasswordLength) {
          setNotice(t('passwordTooShort'))
          return
        }
        if (passwordForm.next !== passwordForm.confirm) {
          setNotice(t('passwordMismatch'))
          return
        }
        run('password/set', { current: passwordForm.current, next: passwordForm.next }, () => {
          setPasswordForm({ current: '', next: '', confirm: '' })
          setNotice(t('passwordSaved'))
        })
      }

      const entryListening = status.listener.state === 'listening'
      const bindable = status.addresses.filter(entry => entry.bindable)
      const savedHost = status.listener.host
      const savedMissing = savedHost !== '' && !bindable.some(entry => entry.address === savedHost)
      const remaining = invite === undefined ? 0 : Math.max(0, Math.round((invite.expiresAt - now) / 60_000))

      return h('div', { style: S.page },

        h('div', { style: S.card },
          h('div', { style: S.between },
            h('h2', { style: S.h2 }, t('title')),
            h('button', { type: 'button', style: S.button, onClick: () => load() }, t('refresh'))),
          h('p', { style: S.muted }, t('subtitle')),
          h('p', {
            style: {
              ...S.muted,
              fontWeight: 600,
              color: entryListening ? 'var(--dsw-alias-state-success-primary)' : status.listener.error === undefined ? 'var(--dsw-alias-label-secondary)' : 'var(--dsw-alias-state-error-primary)',
            },
          }, entryListening ? t('entryOn') : t('entryOff')),
          status.listener.error === undefined ? null : h('p', { style: S.error }, fill(t('entryError'), { reason: status.listener.error })),
          status.listener.url === undefined ? null : h('div', { style: S.item },
            h('span', { style: S.label }, t('entryUrl')),
            h('span', { style: S.mono }, status.listener.url),
            h('div', { style: S.row },
              h(CopyButton, { t, value: status.listener.url }),
              h('a', { href: status.listener.url, target: '_blank', rel: 'noreferrer', style: { ...S.button, textDecoration: 'none', display: 'inline-flex', alignItems: 'center' } }, t('open')))),
          h('p', { style: S.muted }, status.upstream.ok === true
            ? fill(t('upstreamOk'), { authority: status.upstream.authority })
            : fill(t('upstreamBad'), { reason: status.upstream.error })),
          h('p', { style: status.upstream.ok === true && status.upstream.credential.state === 'ready' ? S.ok : S.muted },
            status.upstream.ok !== true
              ? ''
              : status.upstream.credential.state === 'ready' ? t('credentialReady')
                : status.upstream.credential.state === 'failed' ? fill(t('credentialFailed'), { reason: status.upstream.credential.error })
                  : t('credentialIdle'))),

        h('div', { style: S.card },
          h('h2', { style: S.h2 }, t('entry')),
          h('p', { style: S.muted }, t('hostHint')),
          bindable.length === 0 && !savedMissing
            ? h('p', { style: S.warn }, t('hostEmpty'))
            : h('label', { style: S.label }, t('hostLabel')),
          savedMissing ? h('p', { style: S.warn }, fill(t('hostMissing'), { address: savedHost })) : null,
          bindable.length === 0 && !savedMissing ? null : h('select', {
            style: S.input,
            value: form.host,
            onChange: (event) => setForm({ ...form, host: event.target.value }),
          }, [
            // Keep a saved address selectable even when its interface is gone,
            // so the control never silently shows a different address.
            ...savedMissing ? [h('option', { key: savedHost, value: savedHost }, `${savedHost} · ?`)] : [],
            ...bindable.map(entry => h('option', { key: entry.address, value: entry.address },
              `${entry.address} · ${kindLabel(t, entry.kind)} · ${entry.iface || entry.family}`)),
          ]),
          h('div', { style: S.row },
            h('label', { style: S.label }, t('portLabel')),
            h('input', {
              style: { ...S.input, width: 96 },
              type: 'number',
              min: 1,
              max: 65535,
              value: form.port,
              onChange: (event) => setForm({ ...form, port: event.target.value }),
            }),
            h('label', { style: { ...S.row, gap: 6, fontSize: 13 } },
              h('input', {
                type: 'checkbox',
                checked: form.enabled,
                onChange: (event) => setForm({ ...form, enabled: event.target.checked }),
              }),
              t('enableLabel'))),
          h('label', { style: S.label }, t('allowLabel')),
          h('input', {
            style: S.input,
            type: 'text',
            value: form.allowFrom,
            placeholder: '100.64.0.0/10',
            onChange: (event) => setForm({ ...form, allowFrom: event.target.value }),
          }),
          h('p', { style: S.muted }, t('allowHint')),
          h('div', { style: S.row },
            h('button', { type: 'button', style: S.primary, disabled: busy || bindable.length === 0, onClick: applyEntry },
              busy ? t('applying') : t('apply')))),

        h('div', { style: S.card },
          h('h2', { style: S.h2 }, t('password')),
          status.password.set
            ? h('p', { style: S.ok }, fill(t('passwordSet'), { when: ago(t, status.password.updatedAt) }))
            : h('p', { style: S.warn }, t('passwordMissing')),
          status.password.set ? h('input', {
            style: S.input,
            type: 'password',
            autoComplete: 'current-password',
            placeholder: t('passwordCurrent'),
            value: passwordForm.current,
            onChange: (event) => setPasswordForm({ ...passwordForm, current: event.target.value }),
          }) : null,
          h('input', {
            style: S.input,
            type: 'password',
            autoComplete: 'new-password',
            placeholder: t('passwordNext'),
            value: passwordForm.next,
            onChange: (event) => setPasswordForm({ ...passwordForm, next: event.target.value }),
          }),
          h('input', {
            style: S.input,
            type: 'password',
            autoComplete: 'new-password',
            placeholder: t('passwordConfirm'),
            value: passwordForm.confirm,
            onChange: (event) => setPasswordForm({ ...passwordForm, confirm: event.target.value }),
          }),
          h('div', { style: S.row },
            h('button', { type: 'button', style: S.primary, disabled: busy, onClick: savePassword }, t('passwordSave')),
            status.password.set
              ? h('button', {
                type: 'button',
                style: S.button,
                disabled: busy || entryListening,
                onClick: () => run('password/clear', { current: passwordForm.current }),
              }, t('passwordClear'))
              : null),
          h('p', { style: S.muted }, fill(t('minLength'), { n: status.limits.minPasswordLength }))),

        h('div', { style: S.card },
          h('div', { style: S.between },
            h('h2', { style: S.h2 }, t('invite')),
            h('span', { style: S.chip }, fill(t('inviteActive'), { n: status.invites.length }))),
          h('p', { style: S.muted }, t('inviteHint')),
          invite === undefined
            ? h('div', { style: S.row },
              h('button', { type: 'button', style: S.primary, disabled: busy, onClick: () => run('invite/create', {}, (value) => setInvite(value)) }, t('inviteCreate')),
              status.invites.length === 0 ? null : h('button', { type: 'button', style: S.button, disabled: busy, onClick: () => run('invite/cancel') }, t('inviteCancel')))
            : h('div', { style: S.item },
              h('span', { style: S.label }, fill(t('inviteCode'), { minutes: remaining })),
              h('div', { style: S.between },
                h('span', { style: S.code }, invite.code),
                h(CopyButton, { t, value: invite.code })))),

        h('div', { style: S.card },
          h('div', { style: S.between },
            h('h2', { style: S.h2 }, t('sessions')),
            status.sessions.length === 0
              ? null
              : h('button', {
                type: 'button',
                style: S.button,
                disabled: busy,
                onClick: () => {
                  if (window.confirm(t('sessionAllConfirm'))) run('sessions/revoke-all', {})
                },
              }, t('sessionAll'))),
          h('p', { style: S.muted }, fill(t('sessionExpires'), { days: status.sessionDays })),
          status.sessions.length === 0
            ? h('p', { style: S.muted }, t('sessionEmpty'))
            : h('div', { style: S.list }, status.sessions.map(session => h('div', { key: session.id, style: S.item },
              h('div', { style: S.between },
                h('span', { style: { fontWeight: 600, color: 'var(--dsw-alias-label-primary)' } }, session.label),
                h('span', { style: S.mono }, session.address)),
              h('div', { style: S.row },
                h('span', { style: S.chip }, `${t('sessionCreated')} ${ago(t, session.createdAt)}`),
                h('span', { style: S.chip }, `${t('sessionSeen')} ${ago(t, session.lastSeenAt)}`),
                h('span', { style: S.chip }, session.via === 'invite' ? t('sessionViaInvite') : t('sessionVia')),
                session.revokedAt === null ? null : h('span', { style: { ...S.chip, color: 'var(--dsw-alias-state-error-primary)' } }, t('off')),
                h('button', {
                  type: 'button',
                  style: S.button,
                  disabled: busy,
                  onClick: () => {
                    const label = window.prompt(t('sessionName'), session.label)
                    if (label !== null && label.trim() !== '') run('sessions/rename', { id: session.id, label })
                  },
                }, t('sessionRename')),
                session.revokedAt === null
                  ? h('button', { type: 'button', style: S.button, disabled: busy, onClick: () => run('sessions/revoke', { id: session.id }) }, t('sessionRevoke'))
                  : null))))),

        notice === undefined ? null : h('p', { style: S.warn }, notice),

        h('div', { style: S.card },
          h('h2', { style: S.h2 }, t('securityTitle')),
          h('p', { style: S.muted }, t('securityBody'))),

        h('div', { style: S.card },
          h('div', { style: S.between },
            h('h2', { style: S.h2 }, t('transportTitle')),
            h('span', { style: S.chip }, `${status.mobile.stylesheet ? t('on') : t('off')}`)),
          h('p', { style: S.muted }, t('transportBody')),
          h('p', { style: { ...S.muted, ...S.mono } }, fill(t('diagLine'), {
            state: status.listener.state,
            allow: status.listener.allowFrom.length === 0 ? t('allowNone') : status.listener.allowFrom.join(' '),
            days: status.sessionDays,
            ttl: status.invite.ttlMinutes,
          }))),
      )
    }

    /**
     * Render-time safety net. A throwing slot entry blanks the whole panel in
     * this shell, so the page always renders inside this boundary: a failure
     * becomes one readable line instead of an empty screen.
     */
    class SectionBoundary extends React.Component {
      constructor(props) {
        super(props)
        this.state = { error: undefined }
      }

      static getDerivedStateFromError(error) {
        return { error }
      }

      componentDidCatch(error) {
        // The shell's console is the only place this reaches a developer.
        if (typeof console !== 'undefined') console.error('dsh-remote-control: section render failed', error)
      }

      render() {
        if (this.state.error !== undefined) {
          return h('div', { style: S.page },
            h('p', { style: S.error }, `${this.props.t('crashed')}: ${String(this.state.error?.message ?? this.state.error)}`),
            h('p', { style: S.muted }, this.props.t('crashedHint')))
        }
        return this.props.children
      }
    }

    /** Slot entry: the boundary wrapping the real page. */
    function RemoteControlShell(props) {
      return h(SectionBoundary, { t: props.t }, h(RemoteControlSection, props))
    }

    return {
      inject: ['slots', 'locale', 'connection'],
      apply(ctx) {
        ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-remote-control: dictionaries')
        const t = ctx.locale.bind(NS)
        // Its own channel, admitted by the same trust fence and browser cookie
        // as `/api`: the shared `/api` channel belongs to the Typert Gateway.
        // The envelope arrives un-unwrapped: resolve values, reject failures so
        // the page can show one message per action.
        const call = (method, args) => ctx.connection.rpc
          .call('/remoteControl', method, args ?? null)
          .then((result) => {
            if (result?.ok !== true) {
              throw new Error(result?.error?.message ?? `remote-control/${method} failed`)
            }
            return result.value
          })

        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'remote-control',
          order: 30,
          label: () => t('nav'),
          locale: NS,
          inject: () => ({ t, call }),
        }, RemoteControlShell))

        // A phone that slept loses its socket without a close event the page
        // can see, so the reconnect ladder may already have given up. Re-open
        // the connection the moment the page is visible again.
        ctx.effect(() => {
          const onVisible = () => {
            if (document.visibilityState !== 'visible') return
            if (ctx.connection.state.getSnapshot() !== 'connected') ctx.connection.reconnect()
          }
          document.addEventListener('visibilitychange', onVisible)
          window.addEventListener('pageshow', onVisible)
          return () => {
            document.removeEventListener('visibilitychange', onVisible)
            window.removeEventListener('pageshow', onVisible)
          }
        }, 'dsh-remote-control: resume reconnect')
      },
    }
  },
})
