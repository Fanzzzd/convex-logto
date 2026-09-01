# Convex + Logto：认证存储、首屏启动与安全默认值研究

> 调研日期：2026-08-12  
> 范围：`convex-logto` 的 React/Web SPA 集成、可选 BFF 模式、OAuth/OIDC callback 与 Logto webhook。React Native 不在本文结论范围内。  
> 资料原则：只引用标准、官方文档和官方源码。一些浏览器应用规范正在 RFC Editor 最终编辑阶段；本文同时链接当前 IETF 草案与 RFC-to-be 10017，避免把尚未正式发布的编号误写成已发布 RFC。

## 结论先行

1. **现在的 localStorage 不是 `convex-logto` 自己选择的。** `ConvexLogtoProvider` 使用 `@logto/react`，后者默认实例化 `@logto/browser`；Logto 的 `BrowserStorage` 把 `idToken`、`refreshToken`、`accessToken` 放在 localStorage，把包含 `state`、PKCE `codeVerifier`、`redirectUri` 的 `signInSession` 放在 sessionStorage。`convex-logto` 只调用 Logto 的 token API，没有自己写入 localStorage。
2. **localStorage 是 Logto SPA SDK 的官方默认，但不是整个行业一致推荐的“最安全方案”。** Auth0 SPA SDK 默认内存、允许显式选择 localStorage；Okta Auth JS 默认 localStorage；Clerk 采用“HttpOnly 长期 client token + 约 60 秒、JavaScript 可读的 app session token”的混合架构。领先实践不是某一种浏览器 API，而是先按风险选择架构。
3. **不能把 localStorage 简单改成 cookie 就获得安全性。** JavaScript 设置的 cookie 不能带 `HttpOnly`，对 XSS 没有本质改善，还会被浏览器自动随请求发送，带来 cookie/CSRF 设计责任。真正的 `HttpOnly` cookie 必须由同站服务端/BFF 设置，并由服务端持有 OAuth token；这是架构变更，不是 storage 选项。
4. **面向普通 Convex SPA，建议默认继续使用 Logto 官方 Authorization Code + PKCE 客户端，但必须明确其 XSS 威胁模型。** 这与 Convex 浏览器客户端直连 WebSocket 的模型最契合。要减少风险，应缩小 scope、确保 Logto 对 public client 启用 refresh-token rotation/过期策略、严格防 XSS，并提供 BFF/token-mediating 高安全模式，而不是宣称 localStorage“安全”。
5. **首开卡顿和 localStorage 关系很小。** 当前最明显的启动瀑布来自先连 Convex、执行公开配置 query、再构造真实 Logto client，以及 loading→ready 时重建 Provider 子树。`endpoint` 与 `appId` 都是公开配置，默认应同步静态传入；runtime query 应降为有明确用途的兼容/多租户选项。
6. **callback 应由固定、精确的 callback URI 和 Logto SDK 的事务状态驱动。** 不能只凭任意页面 URL 中出现 `code`/`state` 就进入 callback loading。当前 SDK 已校验已保存的 redirect URI、state 和 PKCE verifier，`convex-logto` 不应另造一个更宽松的 URL 分类器充当入口。
7. **当前 webhook HMAC 原始字节验签方向正确，但“验签成功”不等于“不可重放”。** Logto 会对失败交付最多自动重试三次，因此 handler 必须幂等；还应校验签名后的 `createdAt` 新鲜度，并以已验证签名或 raw-body digest 做短期去重。`hookId` 是 webhook 配置 ID，不是单次事件 ID，不能单独用于去重。

## 1. 标准给出的架构顺序

OAuth 浏览器应用最新 BCP 工作把架构按安全性从高到低列为：

1. Backend for Frontend（BFF）：BFF 是 confidential client，token 只在服务端，浏览器只有 cookie session，所有资源请求经 BFF 转发。
2. Token-mediating backend：服务端持有 refresh token，通过 cookie session 向前端按需发短期 access token；前端仍直连资源服务。
3. Browser-based OAuth client：SPA 自己完成 code exchange 并持有 token。

来源：[IETF browser-based apps draft §6](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-27#section-6)、[RFC-to-be 10017 §6](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-6)。截至调研日，该文档已获 IESG 批准并分配 RFC 10017，但仍处于 [RFC Editor Final Review](https://queue.rfc-editor.org/final-review/rfc10017/)。

所有浏览器模式都应使用 Authorization Code，而不是 Implicit flow；public SPA 必须使用 PKCE。OAuth Security BCP 还要求 public client 的 refresh token 使用 sender constraint 或 refresh-token rotation，并应在闲置后过期。来源：[RFC 9700 §2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1)、[RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2)、[browser-based apps draft §6.3.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-27#section-6.3.2)。

这意味着“行业领先默认值”不能脱离产品边界来回答：

| 场景 | 合适默认 | token 是否暴露给页面 JS | 复杂度 |
| --- | --- | --- | --- |
| 普通静态 SPA、Convex 浏览器直连 | Authorization Code + PKCE 的 browser client | 是 | 低 |
| 商业应用、个人数据、较高安全要求，同时仍需浏览器直连 Convex | token-mediating backend | 短期 ID/access token 是；refresh token 否 | 中 |
| 高价值操作、所有 API 可经服务端代理 | Full BFF | 否 | 高 |

IETF 明确“强烈推荐”商业应用、敏感应用和处理个人数据的应用使用 BFF；同时也明确 BFF 会增加服务端部署和全量代理负担。来源：[RFC-to-be 10017 §6.1.4](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-6.1.4)。

### Convex 特有约束

Convex 的 React 客户端通过 `ConvexProviderWithAuth` 从身份提供方拿 JWT，再由浏览器直连 Convex，Convex 对 WebSocket/RPC 验证 OIDC ID token。来源：[Convex Authentication overview](https://docs.convex.dev/auth/overview)、[Convex Custom OIDC Provider](https://docs.convex.dev/auth/advanced/custom-auth)。

因此：

- 只要保留 `ConvexReactClient` 从浏览器直接连接 Convex，页面 JS 就需要在某个时刻得到可交给 Convex 的 ID token。这最多是 **token-mediating backend**，不是“token 永不进浏览器”的 full BFF。
- Full BFF 必须把 Convex 调用也代理到服务端，或采用另一套不向浏览器暴露 bearer token 的会话/网关设计；这会失去或重做一部分 Convex 的浏览器实时订阅模型。

这一区分必须出现在库文档中，不能把“服务端保护 refresh token、仍向浏览器返回 ID token”宣传为 full BFF。

## 2. localStorage 到底是不是推荐方式

### 2.1 它解决了什么

localStorage 的价值主要是 UX：

- 完整页面刷新后仍能恢复登录；
- 多 tab 共享；
- 不依赖身份服务的第三方 cookie/silent iframe 可用性。

Logto React 快速开始明确说明退出时会清除内存和 localStorage 中的 Logto 数据，并且 SDK 默认始终请求 `offline_access`；也就是说，持久化 refresh token 是其 SPA 连续会话设计的一部分。来源：[Logto React quick start](https://docs.logto.io/quick-starts/react)。

### 2.2 它不能防什么

localStorage 对同源 JavaScript 完全可读。若任意一段同源代码被 XSS、供应链脚本或第三方 tag 劫持，攻击者可以直接读取并外传 ID/access/refresh token。localStorage 还跨刷新、跨 tab 持久化，使一次读取型 XSS 能带走较长期 credential。

IETF 的浏览器存储分析明确指出：localStorage 对整个 origin 开放、长期存在、不能阻止恶意同源 JavaScript 读取，而且同步 API 会阻塞 JavaScript；sessionStorage 只是把生命周期缩到 tab，并没有 XSS 隔离。来源：[RFC-to-be 10017 §8.5](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-8.5)。OWASP 也明确建议不要把 session identifier/token 存在 localStorage。来源：[OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis)、[OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#html5-web-storage-api)。

更重要的边界是：即使 Web Worker 完全隔离了已存 token，能在应用 origin 执行恶意 JS 的攻击者仍可能启动新的授权流程，获得自己的一套 token；所以“把 token 换个浏览器存储位置”不是完整的 XSS 答案。来源：[RFC-to-be 10017 §5.1.3](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-5.1.3)、[§8](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-8)。

### 2.3 业界默认并不一致

| 产品/SDK | 官方默认或核心方式 | 官方说明的权衡 |
| --- | --- | --- |
| Logto React/Browser | token localStorage；登录事务 sessionStorage | 持久恢复；SPA public client 配合 PKCE、短期 access token、refresh-token rotation |
| Auth0 SPA SDK | 默认 memory；可选择 `cacheLocation: "localstorage"` | memory 刷新即丢；localStorage 可持久但 XSS 可读 |
| Okta Auth JS | TokenManager 默认 localStorage，可选 sessionStorage/cookie/memory/custom | 强调 custom provider 会接收 raw sensitive token |
| Clerk | 长期 client token 位于 Clerk FAPI 域的 HttpOnly cookie；app 域另有约 60 秒且 JS 可读的 `__session` token | 用极短 token 限制 JS 可读 credential 的窃取窗口；并非“所有 token 都是 HttpOnly” |

来源：[Auth0 SPA SDK storage options](https://auth0.com/docs/libraries/auth0-single-page-app-sdk#change-storage-options)、[Okta Auth JS storageManager](https://github.com/okta/okta-auth-js#storagemanager)、[Clerk architecture](https://clerk.com/docs/guides/how-clerk-works/overview#clerk-s-cookies-and-tokens-in-detail)、[Logto SPA application security model](https://docs.logto.io/integrate-logto/application-data-structure#application-types)。

所以准确表述是：**localStorage 是常见 SPA 兼容性选择，也是 Logto 当前官方 SDK 默认；它不是高安全应用的首选架构。**

## 3. 当前 `@logto/react` 实际存了什么

本仓库开发依赖为 `@logto/react@4.0.14`，依赖 `@logto/browser@3.0.13` 和 `@logto/client@3.1.8`。这些版本由 Logto 同一发布提交产生：[Logto JS release commit `e9d307c`](https://github.com/logto-io/js/commit/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681)。

### 3.1 精确映射

| 数据 | 当前存储 | key 形态 | 用途 |
| --- | --- | --- | --- |
| ID token | localStorage | `logto:{appId}:idToken` | 恢复认证状态；交给 Convex 验证 |
| Refresh token | localStorage | `logto:{appId}:refreshToken` | access token 过期或强制刷新时换新 token |
| Access token map | localStorage | `logto:{appId}:accessToken` | 按 resource/organization 缓存 access token 和 expiry |
| Sign-in session | sessionStorage | `logto:{appId}:signInSession` | `redirectUri`、可选 `postRedirectUri`、随机 `state`、PKCE `codeVerifier` |
| OIDC discovery/JWKS cache | 默认关闭；启用后 sessionStorage | `logto_cache:{appId}:...` | 避免同一 tab 重复 discovery/JWKS 请求 |

证据：

- [`BrowserStorage` 官方源码](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/browser/src/storage.ts) 对 `signInSession` 特判为 sessionStorage，其余 storage key 进入 localStorage。
- [`@logto/client` 官方源码](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts) 读写 `idToken`/`refreshToken`，并把 access token map 持久化；它在 code exchange 后验证 ID token，再保存三类 token。
- [`@logto/browser` 官方源码](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/browser/src/index.ts) 直接构造 `BrowserStorage(config.appId)`；well-known cache 只有第二个构造参数 `unstable_enableCache` 为 true 时才启用。
- [`@logto/react` Provider 官方源码](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/react/src/provider.tsx) 默认实例化上述 browser client，仅暴露 `LogtoClientClass` 替换入口，没有 `cookie` 或通用 `storage` prop。

### 3.2 是我们“非要这样存”吗

不是。`packages/convex-logto/src/react.tsx` 没有调用 `localStorage.setItem`；它调用 `getIdToken()`、`getAccessToken()`、`clearAccessToken()`，实际存储由 Logto client adapter 完成。

当前 `convex-logto` 确实做了一件会触发 token endpoint 的事：Convex 请求 `forceRefreshToken` 时，代码先 `clearAccessToken()`，再调用 `getAccessToken()`，借 Logto refresh flow 轮换 ID token，最后把新的 ID token 返回给 Convex。这是刷新策略，不是存储策略。

### 3.3 Logto React 能不能配置 HttpOnly cookie

不能直接配置。`LogtoProvider` 的 `LogtoClientClass` 是底层逃生口，但内置 browser client 没有 cookie storage 选项。更根本的是：

- 浏览器 JavaScript 无法创建 `HttpOnly` cookie；只有服务端 `Set-Cookie` 能做到。
- JavaScript 可读 cookie 与 localStorage 一样可被 XSS 读取；而且 cookie 还会自动发送。IETF 明确不建议把 cookie 当作 JavaScript token storage；这与 BFF 中“JS 不可读、刻意随请求发送”的 session cookie 是两种不同模式。来源：[RFC-to-be 10017 §8.1](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-8.1)。

所以从 localStorage 迁移到真正安全的 cookie，必须改为 Logto Traditional Web/confidential client + 服务端 session/BFF。Logto 官方传统 Web 快速开始也把 ID/access/refresh token 放在服务端 session，而不是浏览器 JS。来源：[Logto traditional web quick start](https://docs.logto.io/quick-starts/traditional-web)。

## 4. 对首开性能的判断

### 4.1 localStorage 不是主要卡点

在正常浏览器里，读取几个小 token 的 localStorage 是同步操作，确实会短暂占用主线程，但与网络握手、OIDC discovery、token exchange、Convex WebSocket 认证相比通常不是秒级瓶颈。当前普通回访路径中，`convex-logto` 直接调用 `getIdToken()`；只有 Convex 强制刷新时才调用 token endpoint。

因此“首次打开很卡”更应优先归因于当前 bootstrap：

```text
启动应用
  → 创建/连接 Convex 客户端
  → client.query(configQuery) 获取公开 endpoint/appId
  → 销毁 loading LogtoProvider，创建真实 LogtoProvider
  → Logto 从 storage 恢复状态
  → Convex 请求 ID token 并认证 WebSocket
  → 认证相关 UI 才稳定
```

回调页还可能追加：

```text
OIDC discovery（当前默认不做 session cache）
  → code + PKCE verifier 换 token
  → ID token 验证/JWKS
  → Convex WebSocket 验证 ID token
```

### 4.2 `endpoint` 与 `appId` 应默认静态传入

`appId` 是 OAuth `client_id`。标准明确规定 client identifier 不是 secret，不能单独用来认证 client。来源：[RFC 6749 §2.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.2)。Logto endpoint/issuer 和 discovery metadata 本来就必须向浏览器公开；网络请求也会暴露它。

Logto 官方 React 示例把 `endpoint` 和 `appId` 同步写入前端 `LogtoConfig`；Convex 自己也推荐用 `VITE_`/`NEXT_PUBLIC_` 等公开环境变量在构建时配置客户端 deployment URL。来源：[Logto React quick start](https://docs.logto.io/quick-starts/react#init-logto-provider)、[Convex deployment URLs](https://docs.convex.dev/client/react/deployment-urls)。

因此，默认同步静态传入公开 config：

- 没有安全损失；
- 消除一次冷启动 query/等待；
- 不需要 inert client；
- 不发生 loading→ready 的整棵 Provider remount；
- 登录按钮在首帧即可使用。

runtime query 仍有合理用途：同一前端 artifact 服务多个环境/租户、运行时切换身份域、集中配置或紧急开关。但应成为显式选项，并优先用下列方式：

1. SSR/host page 把公开 JSON 内联到 HTML，无额外 round trip；
2. 静态 `config.json`/edge endpoint 配合 HTTP cache、preload 和超时；
3. 最后才是 Convex query；若使用，应有 timeout、错误 fallback、缓存和不 remount 应用子树的 loading gate。

### 4.3 discovery cache

`@logto/react@4.0.14` 提供 `unstable_enableCache`，启用后用 sessionStorage 缓存 OIDC discovery/JWKS；默认是 false。当前 `convex-logto` 没有把它传给 `LogtoProvider`。源码：[Logto React provider](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/react/src/provider.tsx)、[Logto browser client](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/browser/src/index.ts)。

建议在确认上游版本兼容性后默认启用，至少避免同一 tab 的 sign-in 开始页与 callback 页重复 discovery/JWKS。因为 API 标记为 unstable，库应先收紧/检测 peer version，不能在 `@logto/react >=3` 的无限宽范围内无条件假设该 prop 存在。

## 5. 推荐的 npm 库默认 API

### 5.1 默认 SPA 模式

推荐把同步公开 config 变成主路径：

```tsx
<ConvexLogtoProvider
  client={convex}
  config={{
    endpoint: import.meta.env.VITE_LOGTO_ENDPOINT,
    appId: import.meta.env.VITE_LOGTO_APP_ID,
  }}
  callbackPath="/callback"
  afterSignIn="/"
>
  <App />
</ConvexLogtoProvider>
```

推荐行为：

- `config` 同步必需；`configQuery` 保留为 deprecated/advanced 且与 `config` 互斥。
- `callbackPath` 固定，默认 `/callback`，由库构造 `${window.location.origin}${callbackPath}`；普通调用方不再随意传完整 `redirectUri`。
- `signIn()` 默认只启动上述固定 redirect URI；若支持返回原页面，API 改为 `signIn({ returnTo })`，只允许同源相对路径，或允许应用提供显式校验函数。
- 只有当前 `origin + pathname` 与固定 callback URI 完全相等时才挂载 callback handler；最终是否是本次事务由 Logto `isSignInRedirected()` 决定。
- callback 错误进入可恢复状态/`onAuthError`，不在 render 阶段 throw，不用固定 10 秒作为正常控制流。
- 正常 children 只 mount 一次。同步 config 下不需要 fake Logto client；runtime config 下只渲染独立 `fallback`，config ready 后首次挂载认证树。
- 默认开启可兼容的 discovery session cache；暴露关闭开关，而不是让每个用户重复付网络成本。
- 提供阶段耗时 hook：`bootstrap_start`、`config_ready`、`logto_restored`、`callback_exchanged`、`convex_authenticated`；日志不得包含 token、code、state 或完整 callback URL。

建议不要暴露一个看似简单的 `storage="cookie"`。它会误导用户以为 JavaScript cookie 等于 HttpOnly/BFF。可以保留高级 `LogtoClientClass` escape hatch，但文档必须标明它不会自动把 SPA 变成 confidential client。

### 5.2 高安全 token-mediating 模式

对于仍要让浏览器直连 Convex 的应用，建议另设明确模式/入口，而不是偷偷替换 SPA storage：

```tsx
<ConvexLogtoSessionProvider
  client={convex}
  sessionEndpoint="/api/auth/session"
  signInEndpoint="/api/auth/sign-in"
  signOutEndpoint="/api/auth/sign-out"
>
  <App />
</ConvexLogtoSessionProvider>
```

服务端职责：

- 使用 Logto Traditional Web App/confidential client；client secret 永不进浏览器。
- 服务端保存 refresh token，优先只在数据库/session store 中保存 token，cookie 只放随机 session ID。
- cookie：`Secure; HttpOnly; SameSite=Strict; Path=/`，不设 `Domain`，支持时使用 `__Host-Http-` 前缀。来源：[RFC-to-be 10017 §6.1.3.2](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-6.1.3.2)。
- 所有 session/token endpoint 做 CSRF 防护：严格 same-origin/CORS、要求会触发 preflight 的自定义 header，或框架成熟的 anti-forgery token；不能只因为 cookie 是 HttpOnly 就忽略 CSRF。来源：[RFC-to-be 10017 §6.1.3.3](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-6.1.3.3)。
- session endpoint 只向页面返回 Convex 当前需要的短期 ID token；refresh token 永不返回，不在浏览器持久化 ID token。
- `forceRefreshToken` 时由服务端刷新 Logto token，再返回新的 ID token。
- session endpoint 必须 `Cache-Control: no-store`，并限制 CORS、Origin、方法与响应内容。

它能阻止 refresh token 被一次 XSS 直接外传并离线长期使用，但页面仍能获得/调用短期 ID token，恶意同源 JS 也可借 cookie 请求新 token；这是 IETF 定义的 token-mediating backend 风险边界。来源：[RFC-to-be 10017 §6.2.4](https://auth48-transition.rfc-editor.org/authors/rfc10017.html#section-6.2.4)。

若要求任何 OAuth/Convex bearer token 都不进入页面 JS，则必须提供 full BFF/网关并代理 Convex 请求；这不适合只靠当前 React Provider 增量实现，应作为独立产品/架构说明。

## 6. SPA 模式的安全基线

既然默认 SPA 模式会把 refresh token 放在 JS 可读存储中，文档和示例必须把 XSS 防护视为认证安全的一部分：

- 使用 React 默认 escaping；严格审计 `dangerouslySetInnerHTML`、富文本、可控 URL 和 DOM sink。
- 部署 strict CSP（nonce/hash；`object-src 'none'`; `base-uri 'none'`），条件允许时加 Trusted Types。CSP 是纵深防御，不是替代输出编码/净化。来源：[OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)、[OWASP CSP](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html#strict-csp)。
- 尽量不加载第三方运行时脚本/analytics；必须加载时固定来源、版本，并评估 SRI/隔离。第三方脚本与应用同权限，可读取同源 localStorage。来源：[OWASP Third Party JavaScript Management](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)。
- 不在同一 origin 托管互不信任的多个应用，因为它们共享 localStorage。
- scopes/resources 最小化；Convex 只需 Logto ID token 时，不要为“可能以后用”添加 API resources/permissions。RFC 9700 要求 audience 与权限最小化：[RFC 9700 §2.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.3)。
- 确认 Logto SPA application 使用 refresh-token rotation、最大/闲置 lifetime，并对登出、密码修改等事件撤销 grant。Logto 官方说明 SPA 无 app secret，依靠 PKCE、严格 redirect/CORS、短期 access token 与 refresh-token rotation：[Logto application types](https://docs.logto.io/integrate-logto/application-data-structure#application-types)。
- token、authorization code、state、callback 完整 URL 不进入日志、Sentry breadcrumbs、analytics 或错误上报。

## 7. Callback、state、PKCE、CSRF 与 open redirect

### 7.1 标准要求

- redirect URI 必须预注册并做精确字符串匹配；不要 wildcard。
- client 与 authorization server 都不能提供把 query 参数任意转发到外站的 open redirector。
- public client 必须使用 PKCE，且用 `S256`；challenge/verifier 必须每次事务唯一。
- client 必须防 callback CSRF。可依赖已确认由 authorization server 强制执行的 PKCE，也可验证一次性 state；OIDC nonce 也可提供相关保护。
- callback 使用过的 state 应失效；authorization code 必须一次性。

来源：[RFC 9700 §2.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1)、[RFC 9700 §4.1.3](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.1.3)、[RFC 9700 §4.7.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.7.1)、[RFC 9700 §4.11](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.11)。

### 7.2 Logto SDK 已经做的正确事情

Logto client 在 `signIn()` 时生成随机 state 与 PKCE verifier/challenge，将 `redirectUri + state + codeVerifier` 放入 sign-in session；callback 时：

1. 必须存在 sign-in session；
2. `isSignInRedirected()` 对比当前 URL 的 `origin + pathname` 与 session 中保存的 redirect URI；
3. `handleSignInCallback()` 验证 callback URI 和 state；
4. 使用保存的 code verifier 换 token；
5. 验证 ID token，保存 token，并删除 sign-in session。

来源：[`@logto/client` sign-in/callback 源码](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/client/src/client.ts)、[`verifyAndParseCodeFromCallbackUri`](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/js/src/utils/callback-uri.ts)、[`useHandleSignInCallback`](https://github.com/logto-io/js/blob/e9d307c9ebfc8a9a7af85b6491314fa84eb8b681/packages/react/src/hooks/index.ts)。

### 7.3 `convex-logto` 应改进的地方

当前 `classifySignInSearch()` 只要任意页面 query 有 `state` + `code` 就标记 pending；它并不知道真实 callback path，也不知道 Logto sign-in session。这会让普通/恶意 URL 触发 auth loading，随后 SDK 因 `isSignInRedirected()` 为 false 而不 exchange，最后依赖 10 秒超时恢复。

建议：

- 固定 callback path/URI，只在 exact callback route 读取 OAuth 参数。
- SDK 的 `isSignInRedirected()` 是 callback 事务真相；query classifier 只能用于展示错误，不能决定全局 auth pending。
- callback route 不需要认证保护，且尽量是最小页面，不载入 analytics/第三方资源；设置 `Referrer-Policy: no-referrer`，避免 authorization code/state 经 referrer 泄漏。RFC 9700 对 authorization response 页面也给出此建议：[RFC 9700 §4.2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.2.4)。
- exchange 完成后立即用 replace navigation 清除 callback query，避免 code 留在 history。
- OAuth error 只在确认为本次 callback transaction 时处理；以 `onAuthError`/可恢复 UI 返回，不在 render throw。
- `afterSignIn`/`returnTo` 默认只接受 `/...` 相对路径。若允许完整 URL，必须固定 same-origin 或显式 allowlist；绝不能直接采用 callback query 中的目标 URL。RFC 9700 禁止 client open redirect：[RFC 9700 §4.11.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.11.1)。

## 8. Webhook replay 与幂等

### 8.1 已做对的部分

当前 `registerLogtoWebhook()`：

- 读取 raw `ArrayBuffer`；
- 用 Web Crypto HMAC-SHA-256 计算 hex；
- constant-time 比较；
- 验签后才解析 JSON；
- 限制为已知 `User.*` payload。

这符合 Logto 官方“必须对 raw body 计算 HMAC，不要用解析后的 body”的要求。来源：[Logto Secure webhooks](https://docs.logto.io/developers/webhooks/secure-webhooks)。使用 Web API 而非 Node crypto 也符合 Convex V8 runtime 要求。

### 8.2 HMAC 不防重放

同一份合法 raw body 和签名在未来仍然合法。当前签名 header 不含独立 timestamp/nonce；payload 中有签名覆盖的 `createdAt`，但当前代码没有检查它。Logto 会在 HTTP >=500 时自动重试，最多三次，因此重复交付是正常行为而不是边缘攻击。来源：[Logto Configure webhooks: Auto-retry](https://docs.logto.io/developers/webhooks/configure-webhooks#monitor-webhook-health-status)。

此外，payload 的 `hookId` 是 webhook **配置**标识，不是事件或 delivery 唯一 ID。来源：[Logto Webhooks request: common fields](https://docs.logto.io/developers/webhooks/webhooks-request#common-fields)。

### 8.3 推荐默认行为

在验签成功之后、执行用户 handler 之前：

1. 严格解析 `createdAt`，拒绝无效日期。
2. 默认只接受例如 `now - 5min <= createdAt <= now + 1min` 的交付；窗口应可配置。Logto 当前三次 retry 是同一次 HTTP send 的短重试，5 分钟足够覆盖正常网络重试；若未来支持延迟队列，需要相应扩大窗口。
3. 计算 `deliveryKey = SHA-256(rawBody)`，或在 HMAC 已验证后使用 `(hookId, signature)`；在 Convex 表中用唯一 index 原子 claim，保存至少 freshness window/业务容忍期。不要只用 `hookId`。
4. 已处理 key 直接返回 200，不能再次执行副作用。
5. handler 本身仍必须幂等：用户同步尽量以 Logto `user.id` 做 upsert/patch，删除不存在的用户视为成功；邮件、计费等外部副作用需要自己的 idempotency key。
6. 对 raw body 设置大小上限并校验 content type；错误响应不要泄露签名 key 或解析详情。
7. 记录 deliveryKey、event、hookId、createdAt、结果和耗时，但不记录 signing key 或敏感完整 payload。

如果库不想强制创建去重表，最低限度也应提供：

- `maxEventAgeMs` / `maxClockSkewMs` 默认开启；
- `deliveryKey` 作为第三个 handler 参数；
- 清晰标注 handler 必须幂等；
- 可选的 Convex dedupe helper/schema 示例。

## 9. 推荐落地顺序

### P0：直接减少首开卡顿，不降低安全性

1. 新增同步 `config={{ endpoint, appId }}` 并作为文档默认；`configQuery` 降为兼容/advanced。
2. 去掉默认启动的 inert client 与 loading→ready Provider remount；应用认证树只 mount 一次。
3. callback 绑定 exact `callbackPath`，让 Logto `isSignInRedirected()` 决定是否 exchange；移除任意页面 query 导致的 10 秒 pending。
4. 启用兼容的 OIDC discovery/JWKS session cache。
5. 添加分段性能观测和无 token 的错误分类。

### P1：把 SPA 安全边界做清楚

1. 文档明确 localStorage 是 Logto upstream 默认、XSS 可读，不宣传为“安全存储”。
2. 固定 redirect URI；`returnTo` same-origin allowlist；callback no-referrer/最小资源/replace URL。
3. 发布 CSP、第三方脚本、scope、refresh-token rotation/lifetime checklist。
4. 暴露可恢复 `onAuthError`，不要 render throw 或静默吞掉全部 refresh 错误。

### P2：Webhook 防重放

1. 验签后做 `createdAt` freshness。
2. 提供 raw-body digest delivery key 与 Convex 原子去重 helper。
3. 明确并测试 retry/idempotency；覆盖合法重复、过期 payload、future skew、并发重复。

### P3：高安全模式

1. 先定义通用 token-mediating session provider 接口。
2. 为 Next.js/TanStack Start 等有同站服务端的框架提供 server adapter：Logto confidential client、server-side token session、HttpOnly cookie、CSRF 防护。
3. 明确这不是 full BFF；若要 token 完全不进 JS，需要独立 Convex proxy/网关方案。

## 10. 最终判断

- **我们哪里做得不好：** 把公开 config query 放进默认关键路径、用 fake Provider 再 remount、callback 判断比 Logto SDK 宽、缺少观测和 webhook 防重放。
- **我们哪里不安全：** 没发现明显认证绕过；主要是继承 Logto SPA localStorage 的 XSS 风险、callback 任意 query 可造成可用性拖延/open-redirect 防线未在 API 上收紧，以及 webhook 只有真实性/完整性校验而无新鲜度/幂等。
- **localStorage 是谁决定的：** Logto Browser SDK；不是 `convex-logto` 手写。Logto SPA 就是这么做的。
- **为什么没有放 cookie：** JS cookie 不等于 HttpOnly，不能解决 XSS。真正安全 cookie 需要服务端/BFF；对 Convex 直连模式只能做到 token-mediating，full BFF 需要代理 Convex。
- **最好的默认：** 对本包现有目标用户，静态公开 config + Logto 官方 SPA PKCE + 精确 callback + discovery cache + 明示 XSS 基线；另提供明确的服务端高安全模式，而不是用一个 `storage="cookie"` 开关制造错误安全感。
