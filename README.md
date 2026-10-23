# dsh-remote-control

给手机开一个进入本机 Harness 的入口：**一个永久密码**，一次设置，长期免密。地址、端口、密码、设备全部在「设置 → 远程控制」里管，即时生效、重启后仍在。

**不负责隧道**：`dsh web` 保持回环绑定、零参数启动；跨网络可达性由你自己的 Tailscale / ZeroTier / 局域网解决。本插件只在你能路由到的那个地址上开一个入口。

```text
手机 ──http://100.x.y.z:3080──▶ [本插件入口：密码门 + 设备会话]
                                        │ ① 没有会话 → 自己的登录页
                                        │ ② 密码正确 → 发会话 Cookie（滑动 180 天）
                                        ▼
                                  反向代理（改写 Host/Origin，注入服务端凭据）
                                        ▼
                                127.0.0.1:3080  ← Harness 本体，原样不动
```

## 为什么是"反向代理 + 密码门"

Harness 本体只有一条认证路径：启动令牌 → 签发的 `dsh-auth-*` Cookie。它**没有密码这个概念**，而 `/api` 与 WebSocket 升级都只认那个 Cookie。要在不改 Harness 的前提下加"永久密码"，就必须有一个"请求到达 Harness 之前"的地方来校验——那就是本插件的入口监听器，它接请求、验密码、再转发给回环上的 Harness。这个角色就是反向代理。

关键设计：**Harness 的凭据由服务端代持**。插件启动时用公开 API 换一次 Harness Cookie 存在内存里（`ctx.connection.authenticatedUrl()`），转发时注入、并把 Harness 返回的 `Set-Cookie` 全部丢弃。手机永远拿不到 Harness 凭据，只持有本插件的会话 Cookie——所以"下线这台设备"是真的下线：删会话、掐断它的 HTTP 与 WebSocket。

## 能力

**入口与会话**
- 在设置页从本机网卡里挑一个地址（`100.64/10` 标为 Tailscale、私网段标为内网），设端口，点「应用」即生效；换地址是新地址先绑定成功才关旧地址，失败不动现有配置。
- 拒绝通配地址（`0.0.0.0`/`::`）：那会同时打开所有网卡。允许 `allowFrom` CIDR 白名单，例如只放行 `100.64.0.0/10`。
- 永久密码：scrypt(N=16384) 存哈希，至少 8 位；改密码即轮换签名密钥，所有设备重新登录。
- 一次性邀请码：6 位无歧义码、10 分钟、单次使用，交给临时使用的人；状态文件只存 SHA-256。
- 设备会话台账：名称、来源地址、登录/活跃时间、登录方式（密码/邀请），可重命名、单台下线、全部下线。会话 180 天滑动续期。
- 登录限速：每地址每分钟 5 次，连续失败指数退避至 15 分钟，失败与密码错误统一文案。

**传输与移动端**
- HTTP 流式透传：上传（拖文件、附件）、SSE 长响应都不缓冲；WebSocket（`/api/remote.mux`）按原始字节双向管道，实时消息照常到手机。
- 窄屏样式（iOS 输入框 16px 防缩放、安全区、触摸目标）由 Host 注入，全部包在媒体查询里，桌面布局零影响。
- 页面回到前台时主动重连：手机息屏后 socket 静默死亡，这是浏览器侧唯一可靠的修复点。

## 安装与使用

```bash
# 用安装工具落盘（不要手写 profile 的 package.json / cordis.patch.yml）
plugin_manager action=install_bundle target=/绝对路径/dsh-remote-control
```

1. 照常启动 Harness（**不需要任何参数**，保持默认回环绑定）：

   ```bash
   dsh web
   ```

2. 设置 → 远程控制：
   - 「监听地址」选 Tailscale 地址（如 `100.101.102.103`）或局域网地址，端口默认 `3080`；
   - 设「永久密码」；
   - 打开「开启入口」→ 应用。成功后卡片上给出入口地址。
3. 手机（同一 tailnet / 同一局域网）打开该地址，输入密码即可。之后长期免密，除非你下线该设备或改密码。
4. 临时借用：生成一次性邀请码，让对方用码登录（不需要密码），用完可随时下线。

> 端口说明：Harness 在 `127.0.0.1:3080`，入口在 `100.x:3080`，不同地址不冲突。若你把 Harness 也绑到了同一个地址，应用时会报 `EADDRINUSE`，把入口换成别的端口即可。

## 安全边界

| 事项 | 结论 |
|---|---|
| 传输加密 | 入口是明文 HTTP，依赖 tailnet（WireGuard）或局域网本身。若需 HTTPS，见路线图；当前不要把它暴露到公网。 |
| 密码强度 | 等于本机权限，务必用长密码；插件只存 scrypt 哈希，日志不记密码、不记邀请码明文。 |
| 手机持有的凭据 | 只有本插件的会话 Cookie（HttpOnly / SameSite=Strict）。Harness 的 Cookie 不下发。 |
| 下线强度 | 撤销即断：会话校验失败 → 登录页；该会话的活跃 HTTP/WebSocket 全部 destroy。改密码/全部下线同时轮换签名密钥。 |
| 遗忘密码 | 本机桌面（回环直连）随时可进设置页重设，无需找回流程。 |
| 开放代理风险 | 目标写死为本机 Harness，绝不按请求头路由；拒绝通配绑定。 |
| 登录端点 | 仅同源 POST；跨站 Origin 直接 403；限速 + 冷却。 |

## 测试与验证

```bash
node --test tests/*.test.mjs    # 54 条：逻辑单测 + 真实 socket 的端到端 + 浏览器半静态守卫
node --check index.js client.js lib/*.js
```

端到端用例覆盖：未设凭据拒绝开启、通配地址拒绝、绑定与 URL 上报、登录页、错密码/对密码、代理头改写与凭据替换、2MB 上传流式、SSE 分段到达、WebSocket 隧道双向、无会话升级被拒、白名单 403、**部分字段的 apply 不清空白名单**、撤销并掐断活跃 socket（含**进行中的 HTTP 流**）、改密码强制全下线、邀请码单次有效、坏 CIDR 拒绝、关闭入口、限速冷却。

## 安装后确认

```bash
ls ~/.dsh/remote-control/state.json     # 出现即表示已挂载
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'content-type: application/json' \
  -d '{"type":"client-request","rpcId":"p","method":"ping","payload":{}}' \
  http://127.0.0.1:3080/remoteControl/ping    # 期望 401（路由存在、未带凭据）
```

然后在浏览器「设置 → 远程控制」里：选监听地址（Tailscale 的 `100.x`）→ 设永久密码 → 打开开关 → 应用；手机打开卡片上的入口地址输密码即可。

## 路线图

1. **HTTPS 入口**：设置页填证书/私钥路径，会话 Cookie 自动加 `Secure`。
2. **二维码**：把入口地址渲染成二维码，省掉手机手输。
3. **多入口**：同时监听多个地址（局域网 + tailnet），每个地址独立白名单。
4. **TOTP 二次验证** 与 **会话有效期可配（含"永不过期"）**。
5. **非 owner 权限分级**：把设备接进 `PrincipalMap` / `remoteAccess` 角色体系，实现"只能看会话、不能改设置"。

设计取舍见 [docs/design.md](docs/design.md)；真机验收记录见 [docs/acceptance.md](docs/acceptance.md)。

## License

Apache-2.0 —— 见 [LICENSE](LICENSE)。
