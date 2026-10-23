# dsh-remote-control 设计记录（v2）

面向维护者的决策记录：为什么是"自有监听 + 反向代理 + 密码门"，每条边界在哪里，哪些坑留给后续版本。

## 范围

**做**：把本机 Harness 暴露到一个我们已经能路由到的地址上，用永久密码把关，按设备发/撤会话，并把桌面 SPA 在窄屏上变得可用。
**不做**：隧道、NAT 穿透、自建 WebSocket 协议、多用户/角色分级、TLS 证书签发。

## 拓扑

```text
手机 ──▶ 【dsh-remote-control 入口监听器】(100.x:3080, 明文 HTTP)
           ├── /__rc/login  密码/邀请码登录（自有页面，不触达 Harness）
           ├── 其他 HTTP     会话校验 → 反向代理 ──▶ 127.0.0.1:3080（Harness）
           └── 升级请求      会话校验 → 原始 socket 管道 ──▶ 127.0.0.1:3080
Harness 本体：绑定、认证、Cookie 全部保持原样，零参数启动。
```

## 决策

### D1. 必须有代理层：Harness 没有"密码"

Harness 的浏览器认证只有一条路径：进程启动令牌 → `authorizeIndex` 签发 `dsh-auth-*` Cookie；`/api` 与 WebSocket 升级只认它，`connection/request` 钩子在**认证之后**。要让"永久密码"成立，校验必须发生在请求到达 Harness 之前，而那个位置只能是插件自己的监听器——它接请求、验密码、转发，这就是反向代理。

### D2. 不自造 Harness Cookie

另一条"更短"的路是按 Harness 的内部格式自行 HMAC 签 Cookie（cookie 名、payload 版本、authority 绑定都未导出）。否决理由：上游一改就静默失效；且 WebSocket 升级走 `admit`，撤销挡不住。改用公开 API `authenticatedUrl()` 换取真实 Cookie，服务端代持。

### D3. Harness 凭据只存在于服务端

入口持有 Harness Cookie 的内存副本，转发时注入，并**丢弃 Harness 返回的 `Set-Cookie`**。手机因此只有本插件的会话 Cookie。这条是"下线即断"的前提：客户端不再持有第二套凭据。

代价：Harness 若轮换凭据（例如重启后令牌变化），插件会先吃一个 401，再自动重取一次；仍失败则返回 502 并在设置页亮红灯，不影响本机桌面使用。

### D4. 头改写只做必须的三处

| 头 | 为什么必须改 |
|---|---|
| `Host` | Harness 信任栅栏只接受回环/绑定字面量；且代持 Cookie 的 audience 就是 `127.0.0.1:<port>`，两边必须一致 |
| `Origin` | 栅栏会比较 Origin 与 Host，不改就按跨站拒绝（403） |
| `Cookie` | 换成代持凭据；同时保证手机的会话 Cookie 不外泄给 Harness |
| `Referer` | 顺带改写 origin，避免未来某处校验踩坑 |

响应方向：丢掉 `set-cookie`；绝对 `Location` 改回手机用的 authority；hop-by-hop 头（`connection`、`transfer-encoding` 等）按实际帧重算。

### D5. 只允许具体地址，永不通配

`0.0.0.0` 会同时打开所有网卡（包括公网口），上游也明确拒绝这种配置。入口只接受"本机某个具体地址"，且默认不开启——用户必须在设置页显式挑选并打开。

### D6. 密码与会话

- scrypt(N=16384, r=8, p=1) + 每密码独立 salt，`timingSafeEqual` 比较；参数写死，不给 UI 调，避免把强度调弱。
- 会话 Cookie = `<id>.<HMAC(secret,id)>`，`HttpOnly; SameSite=Strict; Path=/`；180 天滑动续期（写盘按分钟合并）。
- 改密码 / 全部下线 → **轮换 secret**，一次作废所有已签发的 Cookie。
- 登录限速：每地址每分钟 5 次，第 5 次失败即进入冷却，指数退避至 15 分钟；失败文案不区分"密码错"与"邀请码错"。

### D7. 邀请码是"免密的一次性会话"

复用 v1 的码表（29 字符、去歧义、单次使用、状态只存 SHA-256）。它不绕过密码体系：兑换出来的是同样一条会话，只是 `via: 'invite'`，便于台账区分与事后下线。

### D8. 绑定变更两阶段

换地址时先在目标地址 `listen()` 成功、才关掉旧监听；同地址换端口则先关后开、失败回滚状态文件。任何失败都把原始 `code`（`EADDRINUSE` / `EADDRNOTAVAIL`）回显到设置页，不静默。

### D9. 移动端只做"不可能错"的部分

- **Host 注入窄屏 CSS**：`webserver/index-inject` 的 `style` 行，全部规则包在媒体查询里，桌面渲染路径不受影响。
- **Client 补前台重连**：手机息屏后 socket 静默死亡、页面看不到 close，重连阶梯可能已耗尽；`visibilitychange`/`pageshow` 时若非 `connected` 就 `reconnect()`。
- **不做布局重排**：没有浏览器控制的验证条件下，重排会把可用页面改成坏页面。

### D10. 消息面

- RPC 走自有频道 `/remoteControl`（`ctx.connection.rpc.handle`）：共享 `/api` 只允许一个拦截器，已被 Typert Gateway 占用。
- 不注册 agent 工具：设密码、发邀请、开入口都属于"授予本机权限"，按 Harness 的用户操作规范只能由用户执行。

### D11. 载体服务的解析方式（已定稿）

插件**不声明** `inject`，由 `resolveServices()` 在激活时解析：先试属性访问（抛错即跳过），再试不会抛错的 `ctx.get`；都不行则每 250ms 重试、最多 30 秒后记一条 warn 并保持入口关闭。

原因（实测）：profile bundle 插入的行里，**属性访问** `ctx.webServer` 会抛 `cannot get property "webServer" without inject`，而 `ctx.get('webServer')` 能取到同一个单例；`ctx.connection` 两条路都通。声明 `inject`（模块级或 patch 行）并不改变这一点，反而让整条 entry 激活失败，所以不声明、运行时解析。

### D13. 为什么不用 `connection.rpc.handle()` 注册频道

它内部是 `const owner = this.ctx`（`rpc-host.ts` 的 `get rpc()`），而 Cordis 的可追踪服务代理会把 `this.ctx` **重绑到"读取该服务的上下文"**——也就是本插件的行。于是 `owner.effect(() => owner.webServer.register(route))` 会在一个访问不到 `webServer` 的上下文里执行，注册阶段就抛错（就是那条 `cannot get property "webServer" without inject` 堆栈）。

因此本插件自己注册：在已解析的 `webServer` 上 `register({ kind: 'prefix', path: '/remoteControl', handler })`，并用公开的 `connection.admit({ headers })` 做认证，自行解析/回写 Connection 信封（`client-request` → `server-response`）。行为与 Connection 频道一致：未认证 401、非 POST 404、非 JSON 415、信封不合法 400。

### D14. 设置页白屏的成因（v1.6.0）

点击「应用」时的渲染序列是：动作成功 → `setForm(undefined)` → 异步 `load()`。中间存在**一帧** `status` 已定义而 `form` 为 `undefined` 的状态，字段渲染直接读 `form.host` 抛错；该槽位没有错误边界，整个面板随之空白。同样的序列会命中"保存密码 / 撤销设备 / 生成邀请"等所有成功动作。

三处修正：

1. **不再清空表单**：改为 `load(true)`，用新的 status 重建表单（`formFromStatus`），动作与重载之间没有空档。
2. **渲染守卫**：`status === undefined || form === undefined` 时只渲染加载态。
3. **错误边界**：槽位改为渲染 `RemoteControlShell`，内部是 `SectionBoundary`（`getDerivedStateFromError`）包住真正的页面——将来任何渲染异常都只显示一行可读报错，不会再白掉整个面板。

另外补了 6 条浏览器半的源码守卫（`tests/client-bundle.test.mjs`）：不得再出现 `setForm(undefined)`、必须有渲染守卫与边界、槽位 id/注入列表正确、以及**每个 `t('key')` 在 zh/en 两份字典里都存在**。

### D12. 代码审查后的加固（v1.3.0）

| 问题 | 处理 |
|---|---|
| 生效在 `next` 参数的开放重定向（`//host`、`/\\host`、控制字符） | `safeNext()` 只接受本站绝对路径，登录页与监听器共用 |
| 限速表按来源地址无界增长 | 512 上限 + 空闲清理 + 最旧淘汰 |
| 撤销只掐 WebSocket，进行中的 HTTP 流（下载/事件流）继续投递 | HTTP 连接也登记到会话，撤销即 destroy（新增端到端用例） |
| 部分字段的 `listener/apply` 会把白名单清空、把入口关掉 | 省略字段 = 保持原值（新增端到端用例） |
| 并发 401 各自兑换一次启动令牌 | 单飞（single-flight）兑换 |
| 端口填 0/空时随机端口重启后漂移 | 绑定后把真实端口写回状态 |
| 上游地址不可写（zoned bind）时抛错穿透到请求处理 | 代理捕获后回答 502 |
| 隧道对上游 connect 无超时 | 8 秒连接超时 |
| 会话台账无上限 | 保留最新 50 条 |
| 清密码后状态仍 enabled，下次启动无法开门 | 清密码同时关闭入口 |
| 未登录的 `/api` 请求收到 200 的 HTML 登录页 | 返回 401 + JSON |
| 保存的地址从网卡消失时下拉框静默显示别的地址 | 保留为独立选项并给出告警 |
| `describeAgent`/cookie 选取靠猜测 | 取根路径交换的第一个 `dsh-auth-*` |

### D15. 桌面版适配

DSH 桌面版是 Electron 外壳 + 同一个 Harness 运行时：`apps/desktop-host` 用 `runProfile({ profile: 'desktop', args: ['--no-open','--host','127.0.0.1','--port','0'] })` 启动完整的 Web 应用，Electron 只负责加载打包前端并把 HTTP/WebSocket 转发给这个 Host。

因此插件**不需要第二套实现**，五个前提在桌面版全部成立：`webServer` 与 `connection` 服务存在（桌面壳自己也用 `connection.authenticatedUrl()` 换 cookie）、上游地址来自 `webServer.getOrigin()`、凭据仍是 launch token → `dsh-auth-*`、客户端插件由 Host 提供、`webserver/index-inject` 照常收集。

真正的差别只有一个：**桌面版每次启动用 OS 分配的端口和新令牌**。由此需要两处修正：

1. **凭据跟随 origin 失效**。`UpstreamCredential` 记录取得 cookie 时的 origin；`ensure()` 发现当前 origin 变了就先作废再取。只在 401 之后补救不够——带 body 的 POST 和 WebSocket 升级都无法重放，旧 cookie 会直接表现为失败请求。
2. **WebSocket 升级遇到 401 时刷新并重试一次**。隧道先读握手响应头再开始管道；若首行是 `HTTP/1.1 401`，说明 Harness 已重启而页面还握着旧 socket，刷新凭据后用同一个请求（含已读的 `head` 字节）重开一条隧道。重试只做一次，避免凭据持续失效时打转。

状态文件仍与 `dsh web` 共用 `~/.dsh/remote-control/state.json`（密码与设备台账互通）；两个实例同时运行时需要给入口设不同端口，这是部署约定而非代码分支。

## 兼容与失效

只读上游公开面：`webServer.{host,port,protocol,getOrigin,register}`, `webserver/index-inject`, `connection.{authenticatedUrl,rpc.handle}`, 客户端 `connection.{rpc,state,reconnect}`、`slots`、`locale`。

- 状态文件 `version: 2`；v1 的 `devices.json` 不兼容（旧 Cookie 绑定的是 Harness authority，无法平移），读到即按空状态处理并重写。
- 卸载插件：监听器关闭（`ctx.effect` 的 teardown）、RPC 频道注销、索引行消失；状态文件保留，重装后密码与设备台账仍在。
- 交付验证边界：端到端测试用真实 socket 覆盖代理/隧道/门禁；浏览器内的设置页视觉与真实 Harness 的联调需要一次 `dsh web` 重启后在页面上确认。
