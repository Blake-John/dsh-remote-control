# CI 与发布

两个工作流，都在 `.github/workflows/`：

| 工作流 | 触发 | 做什么 |
|---|---|---|
| `ci.yml` | push 到 `main`、PR、手动 | Node 22/24 矩阵：清单一致性 → 语法检查 → 54 条测试 |
| `publish.yml` | 推 `v*` 标签、手动 | 标签与版本一致 → 可发布性 → 测试 → 发布到 npm（已存在则跳过） |

## 发布流程

```bash
npm run check                 # 本地等价于 CI：清单 + 测试
git tag -a v2.1.0 -m "…"      # 标签必须是 v + package.json 的版本
git push origin main --tags   # 推送标签即触发发布
```

版本不一致会在第一步就失败（`check-manifest --tag`），不会带着错版本发出去。

## 认证：两种路径，二选一

**A. NPM_TOKEN（最省事）**

1. npmjs.com → Access Tokens → 生成 **Automation** token；
2. 仓库 → Settings → Secrets and variables → Actions → 新建 `NPM_TOKEN`。

**B. OIDC 可信发布（无需长期 token）**

1. 先在 npmjs.com 上创建/拥有该包（首次可用 A 路径发一次）；
2. 包 → Settings → Trusted Publisher → 选 GitHub Actions，填 `owner/repo` 与工作流文件名 `publish.yml`；
3. 仓库里**不要**配 `NPM_TOKEN`，工作流会自动走 OIDC + provenance。

两条路径都带 `--provenance`（构建来源可验证）。同一版本重复推送标签会被"已发布则跳过"挡住，重跑安全。

## 发布前必须成立的三件事

1. **包名**：`package.json` 的 `name` 必须同时出现在 `cordis.patch.yml` 的行名与 `client.js` 的模块 id 里，否则装出来的插件永远不加载——`scripts/check-manifest.mjs` 会挡住；
2. **不要 `private: true`**，且不能用 `@local/` 作用域（不可发布）；
3. **`files`** 必须覆盖运行期文件（`index.js`、`client.js`、`lib/*.js`、`locale/*.json`、`icon.svg`、补丁、README、LICENSE）。

## 首次发布提醒

`dsh-remote-control` 这个名字在 npm 上是否可用未知。如果被占用，改 `package.json` 的 `name`（同时改补丁行名与 `client.js` 的 id，`npm run check` 会告诉你漏了哪个），再走一次标签发布。
