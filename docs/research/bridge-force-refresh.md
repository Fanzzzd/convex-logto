# bridge 模式 forceRefreshToken 是否真的轮换 ID token

> 调研日期：2026-08-13
> 范围：`packages/convex-logto/src/react.tsx:69-87`（`native.tsx:48-64` 同构）的强刷序列 `clearAccessToken()` → `getAccessToken()`（无 resource 参数）→ `getIdToken()`，在 app **未配置任何 API resource** 的目标场景下是否满足 Convex `fetchAccessToken({ forceRefreshToken: true })` 的 contract（必须返回新 token 或 null，不能返回过期缓存）。
> 来源约束：只读本仓库 node_modules 里实际安装的 dist 与 GitHub 上 pin 到具体 commit 的官方源码；不依赖二手文章。客户端 pin 沿用既有研究文档的 [logto-io/js `e9d307c`](https://github.com/logto-io/js/commit/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681)（已核对：该 commit 下 client=3.1.8、js=6.1.2、react=4.0.14、browser=3.0.13，与本仓库安装版本逐一相同）。服务端引 Logto core 所 pin 的 node-oidc-provider fork commit `e048347`。

## 结论先行

1. **当前 bridge 的 forceRefresh 路径是正确的，无需修复。** `clearAccessToken()` 清空整个 access token map 后，`getAccessToken()`（无参）必然缓存 miss，带 refresh token 打 token endpoint；响应里的新 `id_token` 会被 `@logto/client` 验签后写入 storage，随后 `getIdToken()` 从 storage 读到的就是**新** ID token。整条链在客户端源码层逐行成立（见下文 §2 到 §4）。
2. **`clearAccessToken()` 是必要前置，不是多余动作。** 不清缓存时 `#getAccessToken` 会在缓存 access token 未过期时短路返回（[client.ts:542-544](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L542-L544)），不打 endpoint、ID token 不轮换，那才违反 Convex 的强刷 contract。
3. **服务端必定在响应里带新 `id_token`。** Logto core 的 refresh_token grant 无条件调用 `issueIdToken`，只要 grant scope 含 `openid` 就签发新 ID token 并放进响应体；`@logto/client` 的 `normalizeLogtoConfig` 默认强制加入 `openid`（`includeReservedScopes` 默认 true），`convex-logto` 不覆盖该默认。是否带 `resource` 参数不影响此判断（`issueIdToken` 用 grant 级 scope，不用 resource 过滤后的 access token scope）。
4. **refresh token 缺失/过期时失败模式是干净的。** SDK 抛 `LogtoClientError('not_authenticated')` 或 token endpoint 返回 400；`@logto/react` 的 `proxy` 包装把异常吞掉并返回 `undefined`，于是 bridge 的 `if (!(await getAccessToken())) return null` 命中，Convex 转为未认证，不会把过期 ID token 回传给 Convex。
5. **`@logto/client` 公开 API 没有显式"刷新 ID token"的方法。** 全类中除 `#handleSignInCallback`（登录回调）外，唯一写入新 ID token 的路径就是 `getAccessTokenByRefreshToken`，而它只能经 `getAccessToken` / `getOrganizationToken` 触达。当前 bridge 序列就是公开 API 下的规范（也是唯一）做法。
6. 残余风险都很小且已标注（§7）：理论上的微秒级并发竞态、`clearAccessToken` 清掉全部 resource/org token 的性能副作用、以及服务端版本差异（本文以 Logto core master pin 的 fork 为准，未逐版本回溯）。

## 调研版本边界

| 包 | 安装版本（本仓库 node_modules） | pin 源码 |
|---|---|---|
| `@logto/react` | 4.0.14 | [logto-io/js `e9d307c`](https://github.com/logto-io/js/tree/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/react)，`packages/react/package.json` 版本 = 4.0.14 |
| `@logto/browser` | 3.0.13 | 同 commit，版本 = 3.0.13 |
| `@logto/client` | 3.1.8（web 链路）；3.1.2（`@logto/rn@1.1.0` 锁定，native 链路） | 同 commit，版本 = 3.1.8；3.1.2 的 dist 已比对，本报告涉及的三段逻辑逐行等同（见 §6） |
| `@logto/js` | 6.1.2 | 同 commit，版本 = 6.1.2 |
| Logto core（服务端） | 调研日 master = v1.42.0，`packages/core` 依赖 `oidc-provider: github:logto-io/node-oidc-provider#e048347…` | [logto-io/node-oidc-provider `e048347`](https://github.com/logto-io/node-oidc-provider/tree/e04834716e4bfee9f74e8d2e919cae21b2295a8a) |

依赖链：`@logto/react@4.0.14` → `@logto/browser@^3.0.13` → `@logto/client@^3.1.8` → `@logto/js@^6.1.2`（各包 package.json dependencies 实测）。

## 1. `clearAccessToken()` 清什么

[client.ts:565-568](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L565-L568)：

```ts
async #clearAccessToken(): Promise<void> {
  this.accessTokenMap.clear();
  await this.adapter.storage.removeItem('accessToken');
}
```

- 清的是**整个** `accessTokenMap`（内存 Map，key 为 `buildAccessTokenKey(resource, organizationId)`，[utils/index.ts:6](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/utils/index.ts#L6)），以及持久化的 `accessToken` storage 项（BrowserStorage 下即 localStorage 的 `logto:{appId}:accessToken`）。
- **不碰** `idToken` 与 `refreshToken`（那是 `#clearAllTokens` 的事，[client.ts:570-571](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L570-L571)）。所以清完之后 `isAuthenticated()` 仍为 true、refresh token 仍在，后续刷新可用。
- 公开入口 `clearAccessToken` 是 `memoize(this.#clearAccessToken)`（[client.ts:116](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L116)）；`memoize` 只做 in-flight 去重，promise settle 后即从缓存删除（[utils/memoize.ts:15-16](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/utils/memoize.ts#L15-L16)），不会让第二次 clear 变 no-op。

## 2. `getAccessToken()` 无参路径：必打 token endpoint，不短路

[client.ts:534-555](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L534-L555)（`#getAccessToken(resource?, organizationId?)`，无参即两者皆 `undefined`）：

1. 门卫：`isAuthenticated()` = `Boolean(await this.getIdToken())`（[client.ts:166-168](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L166-L168)），只查 ID token **存在性**，不查过期。所以"ID token 已过期但还在 storage"的强刷场景能通过门卫继续走刷新，不会死锁；反之 ID token 被清空（已登出）时抛 `LogtoClientError('not_authenticated')`。
2. 用 `buildAccessTokenKey()`（无参 → key 为 `"@"`）查 map；**缓存命中且未过期时短路返回**（[client.ts:542-544](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L542-L544)）。bridge 已在上一步清空 map，因此这里必然 miss。
3. miss 后落入 `getAccessTokenByRefreshToken(undefined, undefined)`（[client.ts:554](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L554)）。

`getAccessTokenByRefreshToken`（[client.ts:442-489](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L442-L489)）：

- 无 refresh token → 抛 `LogtoClientError('not_authenticated', 'Refresh token not found')`（[client.ts:448-450](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L448-L450)）。
- 否则调 `fetchTokenByRefreshToken({ clientId, tokenEndpoint, refreshToken, resource: undefined, organizationId: undefined })`（[client.ts:456-465](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L456-L465)）。`@logto/js` 侧只有 `resource` 为真值才附 `resource` 参数（[fetch-token.ts:101-103](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/js/src/core/fetch-token.ts#L101-L103)），因此这是一次**纯 OIDC 的 `grant_type=refresh_token` POST**（[fetch-token.ts:91-123](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/js/src/core/fetch-token.ts#L91-L123)）。也不带 `scope` 参数（bridge 不传 `scopes` 选项）→ 服务端按 refresh token 的全部 scope 处理。

也就是说，**无 resource 时它请求的是 OIDC/userinfo 用途的默认 access token，这正是强制 endpoint 往返的载体。**

## 3. 响应中的新 ID token 会被存储，`getIdToken()` 返回新值

响应类型 `SnakeCaseRefreshTokenTokenResponse` 中 `id_token?: string` 为**可选**字段（[fetch-token.ts:44-49](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/js/src/core/fetch-token.ts#L44-L49)）。客户端处理（[client.ts:467-488](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L467-L488)）：

```ts
this.accessTokenMap.set(accessTokenKey, { token: accessToken, scope, expiresAt: requestedAt + expiresIn });
await this.saveAccessTokenMap();
if (refreshToken) {
  await this.setRefreshToken(refreshToken);   // refresh token 轮换也被保存
}
if (idToken) {
  await this.jwtVerifier.verifyIdToken(idToken);   // jose 验签 + iat 偏移 ≤300s 检查
  await this.setIdToken(idToken);                  // ← 新 ID token 写入 storage
}
```

- `setIdToken` 写 storage 的 `idToken` 项（[client.ts:434-436](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L434-L436)）；`getIdToken()` 就是读同一项（[client.ts:181-183](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts#L181-L183)）。bridge 严格 `await getAccessToken()` 之后才 `getIdToken()`，顺序有保证。
- 验签在存储**之前**（`DefaultJwtVerifier.verifyIdToken`，安装 dist `@logto/client/lib/adapter/defaults.js:5-21`，clock tolerance 300s）：验签失败则整个 `getAccessToken` 抛错 → bridge 返回 null，旧 ID token 不会被误当新 token 交给 Convex。

## 4. 服务端：refresh grant 必带新 `id_token` 吗

Logto core（[logto-io/logto master `packages/core/package.json`](https://github.com/logto-io/logto/blob/master/packages/core/package.json)，调研日 v1.42.0）pin 的 oidc-provider fork commit `e048347`：

- refresh_token grant handler 末尾**无条件**调用 `issueIdToken(ctx, refreshToken, at, grant, {...}, scope)`，其中 `scope = ctx.oidc.params.scope ? requestParamScopes : refreshToken.scopes`（[refresh_token.js:189](https://github.com/logto-io/node-oidc-provider/blob/e04834716e4bfee9f74e8d2e919cae21b2295a8a/lib/actions/grants/refresh_token.js#L189) 与 [218-220](https://github.com/logto-io/node-oidc-provider/blob/e04834716e4bfee9f74e8d2e919cae21b2295a8a/lib/actions/grants/refresh_token.js#L218-L220)）。SDK 不传 `scope` 参数 → 取 refresh token 的全部 scope。
- `issueIdToken` 只有一个否决条件：`if (!scopes.has('openid')) return undefined;` 否则签发**全新** ID token（[grant_common.js:162-211](https://github.com/logto-io/node-oidc-provider/blob/e04834716e4bfee9f74e8d2e919cae21b2295a8a/lib/helpers/grant_common.js#L162-L211)）。注意判断用的是 **grant 级 scope**，不是按 resource 过滤后的 access token scope，所以即使带 `resource` 参数，只要 refresh token scope 含 `openid`，仍会签发新 ID token。
- `buildTokenResponse` 把 `id_token: idToken` 放进响应体（[grant_common.js:217-224](https://github.com/logto-io/node-oidc-provider/blob/e04834716e4bfee9f74e8d2e919cae21b2295a8a/lib/helpers/grant_common.js#L217-L224)）。

而 `openid` 必在 scope 里：`normalizeLogtoConfig` 的 `includeReservedScopes` 默认 true（[types/index.ts:51-55, 69-76](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/types/index.ts#L51-L76)），`withReservedScopes` 强制并入 `openid`/`offline_access`/`profile`（[js/src/utils/scopes.ts:7-13](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/js/src/utils/scopes.ts#L7-L13)）；`ConvexLogtoProvider` 构造 config 时从不设 `includeReservedScopes`（本仓库 `packages/convex-logto/src/react.tsx:304-313`）。

**因此在目标场景（无 API resource、convex-logto 默认 config）下，token endpoint 的 refresh 响应恒含新 `id_token`，§3 的 `if (idToken)` 分支恒走。**

## 5. refresh token 缺失/过期时的失败模式

| 情形 | SDK 行为 | bridge 结果 |
|---|---|---|
| storage 里没有 refresh token | `getAccessTokenByRefreshToken` 抛 `LogtoClientError('not_authenticated', 'Refresh token not found')`（client.ts:448-450） | 见下：返回 `null` |
| refresh token 过期/被撤销 | token endpoint 400 `invalid_grant`，requester 抛 `LogtoRequestError` | 返回 `null` |
| Logto 不可达 | fetch 抛网络错误 | 返回 `null` |
| 新 ID token 验签失败（时钟偏移 >300s 等） | `verifyIdToken` 抛错（此时 access token map 已更新，但 idToken 未写） | 返回 `null` |

关键机制在 `@logto/react` 层：`useLogto()` 返回的每个方法都过 `proxy` 包装，`catch` 里只 `handleError(error, …)`（写入 context 的 `error` 状态 + `console.error`），**不 rethrow，函数返回 `undefined`**（[react/src/hooks/index.ts:113-129](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/react/src/hooks/index.ts#L113-L129)；`getAccessToken`/`getIdToken`/`clearAccessToken` 分别在 [134/138/148 行](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/react/src/hooks/index.ts#L134-L148) 被包装）。

于是 bridge 的 `if (!(await getAccessToken())) return null;`（react.tsx:76）正好接住所有失败：Convex 收到 `null` → 干净转为未认证，符合其 contract；不会出现"强刷失败却把过期 ID token 交回去"的循环。顺带说明：web 端 bridge 自己的 `try/catch`（react.tsx:71-84）实际接不到这三个调用的异常（proxy 已吞），是无害的兜底；native 端它是必要的（见 §6）。

## 6. `native.tsx` 同构确认（@logto/rn → @logto/client@3.1.2）

`native.tsx:48-64` 走 `client.clearAccessToken()`（直接调 client 实例，可抛错，故其 `try/catch` 是实际生效的）→ `getAccessToken()` → `getIdToken()`。`@logto/rn@1.1.0` 锁定 `@logto/client@3.1.2`；已比对安装 dist（`node_modules/.pnpm/@logto+client@3.1.2/.../lib/client.js`）：`if (idToken) { verify; setIdToken }`（dist 302-305 行）、`#clearAccessToken` 整 map 清空（365 行）、无 refresh token 抛错（276 行）与 3.1.8 逐行等同。结论对 native 链路同样成立。

## 7. 残余不确定性（诚实标注）

1. **服务端版本覆盖面。** §4 的服务端证据 pin 在 Logto core master（v1.42.0）所用 fork commit；自托管旧版 Logto 用的是更早的 node-oidc-provider（fork 或上游），本次未逐版本回溯。"refresh grant 在 scope 含 `openid` 时签发新 id_token"是 node-oidc-provider 上游长期行为（OIDC Core §12.2 允许），预期跨版本稳定，但这是推断而非逐版本验证。
2. **理论并发竞态。** `getAccessToken` 被 `memoize`（client.ts:97）：若 app 代码恰好在 bridge `clearAccessToken()` 完成前发起了一次会走缓存命中路径的 `getAccessToken()`，bridge 随后的调用会合并到那个 in-flight promise，拿到清缓存前的旧 access token 而不打 endpoint → 该次强刷不轮换 ID token。窗口是几个 microtask 量级，且 `convex-logto` 自身在 web 链路里没有其他 `getAccessToken` 调用方；记录备查，不构成当前 bug。
3. **性能副作用（非正确性）。** `clearAccessToken()` 清的是整个 map：若 app 另行缓存了 resource/organization token，每次 Convex 强刷都会连带清掉它们，下次使用需各自再打一次 refresh grant。当前 convex-logto 默认场景（无 resource）不受影响。
4. 本次为纯源码级验证，未针对该路径补充 live 端到端观测（仓库现有 48 个测试全部通过，但无 forceRefresh 专项用例，可作为后续 ticket 07 的测试补强点）。

## 8. 对 ticket 追问的逐条回答

1. `clearAccessToken()` 清整个 accessTokenMap + 持久化项，不碰 idToken/refreshToken（§1）。
2. 无参 `getAccessToken()` 不短路（map 已被清空）：带 refresh token 打 token endpoint，请求不含 `resource`/`scope` 参数（§2）。
3. 响应含新 `id_token`（服务端恒返回，§4），客户端验签后 `setIdToken` 存入 storage，后续 `getIdToken()` 返回新值（§3）。
4. 链条**确实轮换** ID token，不存在"强刷返回旧 token"的失败模式；`@logto/client` 也没有显式 refresh-ID-token API，当前序列即公开 API 下的规范做法（结论先行 #1/#5）。
5. refresh token 缺失/过期 → SDK 抛错 → react proxy 吞错返回 undefined → bridge 返回 null → Convex 干净登出（§5）。
