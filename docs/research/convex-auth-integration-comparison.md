# Convex 认证集成：凭证存储、WebSocket JWT bridge 与首屏 bootstrap 对照

> 调研日期：2026-08-12  
> 范围：Convex 官方 Auth0、Clerk、WorkOS AuthKit bridge，`@convex-dev/auth`（React / Next.js）、`@convex-dev/better-auth`（React SPA / Next.js）、`@convex-dev/workos-authkit`。  
> 来源约束：只使用各项目官方文档和官方源码；源码链接固定到具体 commit。  
> 目的：回答哪些设计能用于 `convex-logto`，以及哪些设计依赖上游身份服务或 BFF，不能只靠改一个 React Provider 复制。

## 结论先行

1. **Convex bridge 与会话存储是两个不同模块。** `ConvexProviderWithAuth0`、`ConvexProviderWithClerk`、`ConvexProviderWithAuthKit` 都不保存长期凭证；它们只向上游 SDK 要一枚短期 JWT，再交给通用 `ConvexProviderWithAuth`。因此，不能用"Convex 官方也这样集成"来证明某一种 token storage 是安全默认。
2. **直连 Convex WebSocket 时，浏览器 JavaScript 必须在某个时刻拿到 JWT。** Convex 的认证方式是客户端发送协议级 `Authenticate` 消息，应用域 Cookie 不会自动附到 WebSocket。`HttpOnly` 可以保护长期会话根或 refresh token，但不能同时做到"JWT 永不进入 JS"又让浏览器直接连接 Convex；后者需要把 Convex 访问也代理到 BFF。
3. **生态里不存在统一的 `localStorage` 默认。**
   - Convex 官方 Auth0 示例和纯 React `@convex-dev/auth` 确实使用 `localStorage`，优先 reload/跨 tab 体验。
   - Clerk 和 WorkOS 生产架构把长期会话根放在跨域 `HttpOnly` Cookie，只让短期 JWT 进入 JS。
   - Better Auth 的结果取决于拓扑：Next.js 同域时是 `HttpOnly` 会话 Cookie；Vite 跨域适配则把 Cookie envelope 存进 `localStorage`。
4. **最值得 `convex-logto` 借鉴的首屏设计是静态公开配置、稳定 Provider、短 JWT cache 与 SSR seed，而不是首屏配置 query。** 被比较的官方集成都直接从构建期/环境变量传 `domain`、`clientId`、`publishableKey` 或 `redirectUri`，没有在认证前先查询 Convex 再重建整个 Provider。
5. **高安全模式应是一个明确的 BFF/服务端适配，而不是把 `localStorage` 换成普通 Cookie。** 只有服务端写入、`HttpOnly`、`Secure`、合适 `SameSite` 的 Cookie 才能隔离长期凭证；普通 JS Cookie 与 `localStorage` 一样可被 XSS 读取，并额外引入自动携带 Cookie 后的 CSRF 约束。

## 调研版本边界

| 项目 | 截至调研日的版本 / 源码快照 | 备注 |
|---|---|---|
| Convex React client | `convex@1.43.0`；官方 monorepo [`ace2827`](https://github.com/get-convex/convex-backend/tree/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex) | 本仓库 lockfile 当前仍是 `convex@1.41.0`，不能自动假设 1.43 的实验选项可用。 |
| `@convex-dev/auth` | `0.0.95`；release commit [`b58a384`](https://github.com/get-convex/convex-auth/tree/b58a384ced62e771275d27c7d2649d49de2db8ec) | React 与 Next.js 来自同一包。 |
| `@convex-dev/better-auth` | `0.12.5`；release commit [`c628916`](https://github.com/get-convex/better-auth/tree/c628916b451a6b4cff0f5464f134475464b1a6da) | peer Better Auth `>=1.6.11 <1.7.0`；官方示例锁定 `1.6.15`。 |
| `@convex-dev/workos` | `0.0.3`；release commit [`8c9c364`](https://github.com/get-convex/convex-backend/tree/8c9c36411a4229c24382b0a2b1855d3bb10039e1/npm-packages/%40convex-dev/workos) | 这是浏览器侧 `ConvexProviderWithAuthKit` 所在的包。 |
| `@convex-dev/workos-authkit` | `0.2.7`；release commit [`8bf5a88`](https://github.com/get-convex/workos-authkit/tree/8bf5a88ec6453743926167d3d493dbc4058ce7e2) | 这是用户/事件同步的服务端组件，不是 React token bridge。 |
| Auth0 React / SPA SDK | `@auth0/auth0-react@2.24.0`；`@auth0/auth0-spa-js@2.24.1`，源码 [`9992f87`](https://github.com/auth0/auth0-spa-js/tree/9992f878bca44badd494316521e4bd591caabe74) | Convex bridge 返回 `id_token`。 |
| Clerk | Convex 1.43 支持 `@clerk/react` 与旧 `@clerk/clerk-react`；调研日版本分别为 `6.14.1` / `5.61.3` | 存储结论来自 Clerk 官方当前架构文档和官方 `clerk-js` 源码。 |
| WorkOS React | `@workos-inc/authkit-react@0.16.2` / `authkit-js@0.20.2`；源码 [`52b2f03`](https://github.com/workos/authkit-react/tree/52b2f03a312ef7f46a7029ce80273e872fa7f0cd) / [`391f328`](https://github.com/workos/authkit-js/tree/391f328f66bc7aed194ba0fab521021babf72b6a) | `devMode` 的存储方式与生产不同。 |
| WorkOS Next.js（高安全参照） | `@workos-inc/authkit-nextjs@4.3.1`；release commit [`4c6bc93`](https://github.com/workos/authkit-nextjs/tree/4c6bc9322631655d20461c9f369dde821131fcd9) | 不是 `@convex-dev/workos-authkit`，但能说明 BFF/SSR 如何保护长期凭证。 |

版本号用于锁定本次结论，不表示建议在本任务中升级依赖。

## 先看共用的部分：Convex WebSocket JWT bridge 做了什么

### 认证成功以 Convex 后端确认为准

通用 [`ConvexProviderWithAuth`](https://github.com/get-convex/convex-backend/blob/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex/src/react/ConvexAuthState.tsx) 接收的上游接口只有三项：

- `isLoading`
- `isAuthenticated`
- `fetchAccessToken({ forceRefreshToken })`

它先调用 `client.setAuth(fetchAccessToken)`，但只有 Convex 后端接受 JWT、返回 identity transition 后，`useConvexAuth().isAuthenticated` 才会变成 `true`。所以 UI 权限门控应该看 Convex 的状态，而不是只看 Logto/Auth0/Clerk/WorkOS 的本地登录状态。Convex 的 [WorkOS under-the-hood 文档](https://docs.convex.dev/auth/authkit/#under-the-hood) 也明确描述了"取 token → 交给 Convex → 后端验签 → 客户端收到确认"的链路。

Provider 用一个位于其他子组件之前的 effect 调 `setAuth`，并把清理 auth 的 effect 放在子组件之后，目的是让 query 的订阅/退订顺序保持正确。它不会因为认证还在初始化就卸载整个业务子树；安全内容通过 `AuthLoading` / `Authenticated` 状态门控。

### JWT 是协议消息，不是应用 Cookie

[`AuthenticationManager`](https://github.com/get-convex/convex-backend/blob/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex/src/browser/sync/authentication_manager.ts) 取得 JWT 后，通过 Convex sync 协议发送 Authenticate。浏览器无法把应用域的 `HttpOnly` Cookie当作这个消息里的 token 值；而且 Convex 部署通常也是另一个 origin。

这带来一个不可绕过的边界：

- 可把**长期凭证**留在 `HttpOnly` Cookie；
- 可把给 Convex 的**短期 JWT**只放内存，并尽量缩短有效期；
- 但只要浏览器直连 Convex，短期 JWT 就必须短暂地对 JS 可用；
- 若要求"任何 bearer JWT 都不进入 JS"，必须由同源 BFF 代理数据访问，不能再使用当前浏览器直连 Convex 的模型。

### 默认 bootstrap 会先试 cache，再强刷一次

Convex 1.43 的认证状态机默认做三步：先取可能缓存的 token，后端确认后立刻用 `forceRefreshToken: true` 再取一枚新 token，之后根据 `iat` / `exp` 在到期前刷新。这样可以尽快确认 refresh 路径正常，但第二次 Authenticate 可能让认证 query 重跑。

1.42.1 之后有实验性 [`initialAuthTokenReuse`](https://github.com/get-convex/convex-backend/blob/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex/src/browser/sync/client.ts#L140-L155)：缓存 JWT 被后端确认后，按剩余寿命安排刷新，而不立即进行第二次 Authenticate。另一个实验性 [`expectAuth`](https://github.com/get-convex/convex-backend/blob/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex/src/browser/sync/client.ts#L125-L139) 会在首个 auth token 发送前暂停 query/mutation/action。

两者的适用面不同：

- `initialAuthTokenReuse` 是减少重复 auth 和 query 重跑的性能优化；
- `expectAuth` 适合确定为登录后页面的客户端；公共页面会因此更晚开始非敏感 query；
- 如果认证配置本身还要先通过同一个被暂停的 Convex client 查询，`expectAuth` 会形成启动依赖环。这也是把 Logto 的公开配置移出首屏 Convex query 的额外理由。

## 凭证位置总表

表中的"长期凭证"指能维持完整登录会话、反复换取短期 JWT 的材料；"短期 JWT"指直接交给 Convex 的 bearer token。

| 集成 / 拓扑 | 长期凭证 | 给 Convex 的短期 JWT | Cookie 属性与 JS 可见性 | reload 后的恢复路径 |
|---|---|---|---|---|
| Auth0 + Convex 官方 React 示例 | rotating refresh token 连同 access / ID token cache 在 `localStorage` | Auth0 `id_token`，从 SDK cache 读或刷新 | 不是 `HttpOnly`；XSS 可读 | 先读本地 cache，可立即尝试 WS auth；Convex 随后默认强刷 |
| Clerk + Convex | 长期 `__client` 在 Clerk FAPI 域 `HttpOnly` Cookie | 应用域约 60 秒的 `__session` / `convex` template JWT；JS 可读，SDK cache | 长期根 `HttpOnly`；短 token 非 `HttpOnly` | Clerk SDK 用长期 Cookie 向 FAPI mint/刷新短 JWT，再给 Convex |
| WorkOS AuthKit React（生产） | refresh token 在 WorkOS Auth API 域 `HttpOnly` Cookie | access JWT 仅放 JS memory | 长期 refresh 不进 JS；marker Cookie 可让 SDK 判断是否尝试恢复 | marker 存在时先 refresh RTT，得到 user/access token 后再给 Convex |
| WorkOS AuthKit React（localhost 默认 dev mode） | refresh token 在 `localStorage` | access JWT 在 memory | 为本地跨域开发让步，不应当作生产架构 | 从 localStorage refresh token 换新 access JWT |
| `@convex-dev/auth` React | one-time rotating refresh token 在 `localStorage` | 1 小时 JWT 默认也在 `localStorage` | 两者均 JS 可读；自定义 `storage` 可换 session/memory/secure store | 同步读缓存 JWT → WS；必要时用 refresh token 轮换 |
| `@convex-dev/auth` Next.js | 真 refresh token 和 JWT 同时在应用域 `HttpOnly` Cookie；客户端只收到 refresh 的占位字符串 | JWT 默认再落客户端 `localStorage`；可改 `inMemory` | prod 为 `__Host-`、`Secure`、`HttpOnly`、`SameSite=Lax`、`Path=/`；客户端不拿真 refresh token | middleware/server provider 从 Cookie 注入 JWT，客户端无需先刷新；后续 refresh 经同源 POST 代理 |
| Better Auth + React Vite 跨域 | Better Auth session token 原本是 Cookie，但 cross-domain client 把 Set-Cookie envelope 存 `localStorage` 并用自定义头回传 | Convex JWT 默认 15 分钟，Provider 内存 cache；对应 `convex_jwt` Cookie 也可能进入该 envelope | 跨域兼容模式下长期 session 对 JS 可见 | 恢复 Better Auth session 后请求 `/convex/token`，再进行 WS auth |
| Better Auth + Next.js 同域代理 | opaque session token 在应用域 `HttpOnly` Cookie，服务端 session 默认 7 天 | 15 分钟 Convex JWT 存 `HttpOnly` `convex_jwt` Cookie；SSR 可把它作为 `initialToken` 交给客户端 memory | Better Auth 生产 Cookie 默认 `HttpOnly` / `Secure`，session 默认 `SameSite=Lax` | 服务端由 session Cookie 获取/缓存 JWT，随 SSR seed 给 Provider；客户端直接尝试 WS auth |

## 各集成细节

### 1. Convex 官方 `ConvexProviderWithAuth0`

Convex 官方 [Auth0 安装示例](https://docs.convex.dev/auth/auth0#configure-convexproviderwithauth0) 明确设置：

```tsx
<Auth0Provider
  useRefreshTokens={true}
  cacheLocation="localstorage"
  // domain/clientId/redirect_uri 均静态传入
>
```

因此，"Convex 官方 Auth0 quickstart 用了 localStorage"是事实；但这不是 Auth0 自身最安全的默认。Auth0 的[官方 token storage 指南](https://dev.auth0.com/docs/secure/security-guidance/data-security/token-storage) 推荐 SPA SDK，默认把 token 放内存，并解释 `localStorage` 是为跨 reload/跨 tab 持久性接受 XSS 可读风险的备选。其[官方源码](https://github.com/auth0/auth0-spa-js/blob/9992f878bca44badd494316521e4bd591caabe74/src/global.ts)也把 cache location 默认设为 memory；[`LocalStorageCache`](https://github.com/auth0/auth0-spa-js/blob/9992f878bca44badd494316521e4bd591caabe74/src/cache/cache-localstorage.ts)只是显式可选实现。

Convex bridge 本身很薄：[源码](https://github.com/get-convex/convex-backend/blob/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex/src/react-auth0/ConvexProviderWithAuth0.tsx)调用 `getAccessTokenSilently({ detailedResponse: true })`，返回其中的 `id_token`；Convex 要求强刷时把 `cacheMode` 切到 `off`。

可借鉴：

- bridge 不再建立第二套 token storage；会话所有权留给 IdP SDK；
- 明确 honor `forceRefreshToken`，强刷不能仍返回过期 cache；
- `domain` / `clientId` / redirect URI 是公开配置，构建时直接传入。

不可直接照搬：

- 官方 quickstart 的 `localStorage` 选择优化了 reload，不代表行业安全上限；
- Auth0 SDK 有 refresh-token rotation、cache key 和多 tab 协调，不能只复制一个 `localStorage.setItem`。

### 2. Convex 官方 `ConvexProviderWithClerk`

Clerk 的领先点是把长期与短期凭证拆开。Clerk 的[官方架构说明](https://clerk.com/docs/guides/how-clerk-works/overview#clerk-s-cookies-tokens-in-detail)给出：

- 长期 `__client`：位于 Clerk Frontend API 域，`HttpOnly`、`SameSite=Lax`，是会话恢复根；
- 短期 `__session`：位于应用域，约 60 秒，非 `HttpOnly`，因为客户端 SDK 需要读取并作为 header/JWT 使用；
- SDK 约每 50 秒刷新短 token，以保留撤销能力并缩小 XSS exfiltration 后的 bearer 使用窗口。

Convex 的 [Clerk bridge 源码](https://github.com/get-convex/convex-backend/blob/ace28270172bf82db6d308708bb4cc9feb8292e9/npm-packages/convex/src/react-clerk/ConvexProviderWithClerk.tsx)调用 `getToken()`：新 Convex 集成可直接取 `aud=convex` 的 session token，旧配置取 `template: "convex"`；强刷映射为 `skipCache: true`。组织、角色、session ID 变化时会重建 fetcher，从而重新认证。

可借鉴：

- 长期会话根与短期 JS bearer 分层；
- bearer 生命周期显著短于登录会话；
- token fetch 的 cache、跨 tab 协调和刷新都归上游 SDK；
- 组织/租户等会影响 JWT claims 的上下文变化要触发重新取 token。

不可只靠 `convex-logto` Provider 复制：

- `HttpOnly` 长期根在 IdP 自己的 same-site Frontend API 域，并由 IdP mint 60 秒 JWT；这是服务架构，不是 storage 选项；
- Logto 若没有对应的浏览器会话根/短 JWT endpoint，就需要 Logto 服务端 SDK或自建 BFF。

### 3. Convex 官方 WorkOS AuthKit bridge

这里有两个容易混淆的官方包：

- [`@convex-dev/workos`](https://github.com/get-convex/convex-backend/blob/8c9c36411a4229c24382b0a2b1855d3bb10039e1/npm-packages/%40convex-dev/workos/src/index.tsx) 才导出浏览器用的 `ConvexProviderWithAuthKit`；
- [`@convex-dev/workos-authkit`](https://github.com/get-convex/workos-authkit/tree/8bf5a88ec6453743926167d3d493dbc4058ce7e2) 是 Convex 服务端 component，用于用户同步、事件、backfill 和 auth config；其 [`/react` 入口仍是占位](https://github.com/get-convex/workos-authkit/blob/8bf5a88ec6453743926167d3d493dbc4058ce7e2/src/react/index.ts)。

WorkOS React SDK 的[官方源码](https://github.com/workos/authkit-js/blob/391f328f66bc7aed194ba0fab521021babf72b6a/src/utils/session-data.ts)显示，生产默认下 user/access token 在 memory，refresh token 通过 WorkOS Auth API 的 Cookie 使用；[`authenticateWithRefreshToken`](https://github.com/workos/authkit-js/blob/391f328f66bc7aed194ba0fab521021babf72b6a/src/http-client.ts)在 Cookie 模式下发送 `credentials: "include"`，不把 refresh token 放进 JSON body。只有 localhost / `devMode=true` 才把 refresh token 写到 `localStorage`；AuthKit React 的[官方 README](https://github.com/workos/authkit-react/blob/52b2f03a312ef7f46a7029ce80273e872fa7f0cd/README.md#L100-L115)也明确写出这一点。

启动时，SDK 看到 `workos-has-session` marker 后先执行 refresh，得到内存 access token 和 user；这意味着生产安全默认通常要付一次网络 RTT，相关逻辑见 [`create-client.ts`](https://github.com/workos/authkit-js/blob/391f328f66bc7aed194ba0fab521021babf72b6a/src/create-client.ts#L115-L143)。

当前 `@convex-dev/workos@0.0.3` bridge 调用 `getAccessToken()`，却没有把 Convex 的 `forceRefreshToken` 映射成 WorkOS 的 `getAccessToken({ forceRefresh: true })`。因此它可以作为"薄 bridge"参照，但**不应原样复制其强刷行为**。

可借鉴：

- 生产与本地开发可以采用不同的 cookie/storage 策略，但文档必须显式说明；
- transient refresh 失败不应立即销毁仍可能有效的会话，WorkOS 的[官方 session resilience 指南](https://workos.com/docs/authkit/session-resilience)专门区分了网络/429/5xx 与终止性失败；
- 静态 `clientId`、`redirectUri`、API hostname，不阻塞首屏查配置。

### 4. `@convex-dev/auth`：React

这是 Convex 生态里最直接支持"自己签发 session + JWT"的实现。其[安全文档](https://labs.convex.dev/auth/security)明确说明为什么纯 React 默认让 JS 持有凭证：Convex 通常是第三方 origin、浏览器无法用应用的 server-only Cookie 填充 WebSocket Authenticate、React Native 的 Cookie 支持也不一致。

默认 [`ConvexAuthProvider`](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/react/index.tsx) 使用 `localStorage`，并允许调用方注入任意 `TokenStorage`。实际存储键和流程见 [`src/react/client.tsx`](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/react/client.tsx)：

- `__convexAuthJWT`：短期 JWT；
- `__convexAuthRefreshToken`：长期 rolling refresh token；
- `__convexAuthOAuthVerifier`：OAuth verifier；
- 所有键按 Convex deployment URL namespace；
- `storage` event 同步其他 tab 的 JWT；
- `navigator.locks` 或回退 mutex 防止多个 tab 同时 rotate refresh token。

服务器默认 JWT 为 [1 小时](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/server/implementation/tokens.ts)，session 总时长与 inactive 时长默认都是 30 天。refresh token one-time rotation 有 10 秒并发复用窗口，并在窗口外检测旧 token 重用后使后代 token 失效，见 [`refreshSession.ts`](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/server/implementation/mutations/refreshSession.ts)。

这说明 localStorage 可以配合 rotation、reuse detection、多 tab 锁和严格 XSS 防御做出一个可运行的 SPA 权衡；它并没有把 localStorage 变成"安全存储"。

可借鉴：

- storage key 必须按 issuer/app/deployment namespace，不能不同环境共用；
- refresh 要去重、跨 tab 加锁，并对旧 refresh token 做 reuse detection；
- storage 应为显式可替换接口，而不是业务代码散落着直接读写；
- 首屏先用缓存 JWT 认证，refresh 放后台，而不是所有内容等待一次远程配置和远程 refresh。

不可直接照搬：

- Logto refresh token 的轮换与 reuse detection 由 Logto 决定；`convex-logto` 不能在客户端补出服务端保证；
- 把 Logto token 再复制进本库 storage 会制造双写、竞态和退出登录残留，应继续让 Logto SDK做唯一 owner。

### 5. `@convex-dev/auth`：Next.js

Next.js 版本加入同源服务器后，安全边界明显更强。其 [Cookie 源码](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/nextjs/server/cookies.ts)在非 localhost 使用 `__Host-` 前缀，并设置 `Secure`、`HttpOnly`、`SameSite=Lax`、`Path=/`。access JWT、refresh token、OAuth verifier 都有服务端 Cookie。

关键细节是：

- [auth proxy](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/nextjs/server/proxy.ts)只给客户端返回 refresh token 占位符 `"dummy"`，真实 refresh token 永不进入 JS；
- [`ConvexAuthNextjsServerProvider`](https://github.com/get-convex/convex-auth/blob/b58a384ced62e771275d27c7d2649d49de2db8ec/src/nextjs/server/index.tsx)把当前 access JWT 作为 server state 注入客户端；
- 客户端默认会把短 JWT 写到 `localStorage`，但可选 `storage="inMemory"`；
- 后续 refresh 通过同源 POST，proxy 从 `HttpOnly` Cookie 取真 refresh token；
- middleware 在 JWT 接近到期时服务端预刷新，并检查跨 origin 请求。

官方 [Next.js 安全文档](https://labs.convex.dev/auth/authz/nextjs)提醒：Cookie 自动携带意味着服务端 GET 不能产生副作用，否则会形成 CSRF 风险。用了 Cookie 不等于自动安全；这个模式同时需要 method discipline、origin 检查和 SameSite 策略。

可借鉴到 `convex-logto` 的高安全模式：

- 真实 refresh token 只在 `HttpOnly` Cookie / BFF；
- 客户端只收到短期 Convex 可验证 JWT；默认 memory，可选短 JWT persistence；
- SSR 只 seed 短 JWT，不把 refresh token序列化到 HTML；
- refresh endpoint 同源、只接受非 GET，并做 origin/CSRF 校验。

不能在当前纯 SPA API 中假装实现：没有应用服务器就没有地方安全设置/读取 `HttpOnly` Cookie，也没有同源 refresh proxy。

### 6. `@convex-dev/better-auth`：React Vite / 跨域

Better Auth 自身默认是传统的 Cookie session；[官方 session 文档](https://better-auth.com/docs/concepts/session-management)说明 session token 与服务端 session record 的关系，默认 session 7 天；[Cookie 文档](https://better-auth.com/docs/concepts/cookies)说明生产 Cookie 默认 `HttpOnly` / `Secure`，session 默认 `SameSite=Lax`。

然而，Convex-hosted Better Auth API 与 Vite app 是不同站点，Safari 等浏览器会阻断第三方 Cookie。官方 React guide 因此要求 [`crossDomain()` / `crossDomainClient()`](https://labs.convex.dev/better-auth/framework-guides/react)。该 client 的[源码](https://github.com/get-convex/better-auth/blob/c628916b451a6b4cff0f5464f134475464b1a6da/src/plugins/cross-domain/client.ts)会：

1. 读取服务端的 `Set-Better-Auth-Cookie`；
2. 把序列化 Cookie envelope 写进 `localStorage`；
3. 后续请求设 `credentials: "omit"`，把凭证放到 `Better-Auth-Cookie` 自定义 header；
4. 另把 session data cache 写到 `localStorage`。

所以这个跨域模式的 Cookie 名称和签名并不代表长期 session token 对 JS 不可见；对 XSS 而言，它仍是 localStorage bearer。它解决的是跨站 Cookie 可靠性，不是提高 XSS 隔离。

Convex plugin 的[源码](https://github.com/get-convex/better-auth/blob/c628916b451a6b4cff0f5464f134475464b1a6da/src/plugins/convex/index.ts)提供 `/convex/token`，JWT 默认 15 分钟。React [`ConvexBetterAuthProvider`](https://github.com/get-convex/better-auth/blob/c628916b451a6b4cff0f5464f134475464b1a6da/src/react/index.tsx)在 session 存在后请求这个 endpoint，把 JWT cache 放在 React state，并用 promise ref 合并并发 token 请求；强刷时绕过 cached token。它仍然复用 Convex 通用 bridge。

可借鉴：

- promise-level request dedupe，避免 StrictMode、多个订阅和 WS 状态机同时触发相同 token 请求；
- 短期、专门面向 Convex audience 的 JWT，不把上游 session token直接交给 Convex；
- 社交登录跨域 callback 使用短期 one-time token换成本地 session，而不是在 URL 放长期 session token。

不应借鉴为安全默认：

- 把 Cookie envelope 搬进 localStorage 只是受部署拓扑约束的兼容方案；
- `skipStateCookieCheck` 等跨域特殊配置依赖其数据库 state 和 one-time-token 机制，不能脱离完整协议复制。

### 7. `@convex-dev/better-auth`：Next.js / 同域

官方 [Next.js guide](https://labs.convex.dev/better-auth/framework-guides/next)通过应用自己的 `/api/auth` 反向代理 Convex-hosted Better Auth，浏览器看到的是同源 Cookie。于是：

- 长期 Better Auth session token 保持 `HttpOnly` Cookie；
- Convex plugin 同时设置一个默认 15 分钟的 `convex_jwt` Cookie；
- 服务端 [`getToken`](https://github.com/get-convex/better-auth/blob/c628916b451a6b4cff0f5464f134475464b1a6da/src/utils/index.ts)可用 session Cookie 调 `/convex/token`；
- 实验性 `jwtCache` 可直接复用仍有效的 `convex_jwt` Cookie，省掉 server token endpoint RTT；
- layout 把短 JWT 作为 `initialToken` 传给 [`ConvexBetterAuthProvider`](https://github.com/get-convex/better-auth/blob/c628916b451a6b4cff0f5464f134475464b1a6da/src/react/index.tsx)，客户端用 memory cache 立刻开始 Convex WS auth；
- SSR 可用 `preloadAuthQuery` 并把预加载结果交给客户端，减少首屏 waterfall。

这是一种很适合 `convex-logto` 可选 BFF adapter 的性能/安全组合：长期 session `HttpOnly`，短 JWT SSR seed，客户端只在 memory 保存短 JWT。不过需要明确：JWT 被序列化为 client prop 后仍可被页面 JS 读取；它保护的是长期会话，不是让短 token 对 XSS 隐身。

### 8. WorkOS Next.js：更完整的 BFF 参照

Convex 官方 Next AuthKit recipe 使用 `@workos-inc/authkit-nextjs` 的 provider/server action。该 SDK 把 `{ accessToken, refreshToken, user }` seal 后保存在应用域 session Cookie，Cookie 实现见[官方源码](https://github.com/workos/authkit-nextjs/blob/4c6bc9322631655d20461c9f369dde821131fcd9/src/cookie.ts#L33-L127)；官方 README 明确说明 [token 不进入 localStorage/sessionStorage](https://github.com/workos/authkit-nextjs/blob/4c6bc9322631655d20461c9f369dde821131fcd9/README.md#L659-L665)。客户端需要给 Convex JWT 时，通过 Server Action 获取 access token，前端 token store 只缓存于[内存](https://github.com/workos/authkit-nextjs/blob/4c6bc9322631655d20461c9f369dde821131fcd9/src/components/tokenStore.ts#L24-L54)。

性能上还有两种显式选择：

- `initialAuth`：SSR seed 用户认证状态；
- `eagerAuth`：仅把 access token 放进一个约 30 秒、JS 可读的临时 Cookie，首渲染同步消费后删除，以省第一个 Server Action RTT；长期 refresh token 仍不暴露。参见官方 [`eagerAuth` 文档](https://github.com/workos/authkit-nextjs/blob/4c6bc9322631655d20461c9f369dde821131fcd9/README.md#L768-L790)。

这说明安全与首屏速度不一定只能二选一。可以只对短 bearer 做一次性 bootstrap 暴露，长期会话仍留在 `HttpOnly` 边界。但这个模式需要服务端 SDK、加密 Cookie、刷新路由和严格的临时 token 生命周期。

## 首屏 bootstrap 对照

| 集成 | 公开配置来源 | 首屏可能的关键路径 | 是否重建业务子树 | 官方已有的性能手段 |
|---|---|---|---|---|
| Auth0 | 构建期 `domain/clientId/redirect_uri` | SDK cache → ID token → WS 确认；无 cache 时 silent refresh | 否 | localStorage 可避免 reload 丢 token；代价是长期 token XSS 可读 |
| Clerk | publishable key / static config | Clerk load → 必要时向 FAPI mint 60 秒 JWT → WS 确认 | 否 | 长期 HttpOnly 根；短 JWT cache 与自动刷新 |
| WorkOS React | `clientId/redirectUri/apiHostname` | marker → refresh RTT → memory JWT → WS 确认 | 否 | 安全优先，接受首次恢复 RTT |
| Convex Auth React | client/deployment URL + local cache | local JWT → WS 确认 → 默认再 rotate/Authenticate | 否 | local JWT；跨 tab sync；可用 Convex 1.43 实验性 token reuse |
| Convex Auth Next | 服务端 Cookie | middleware/server state JWT → 客户端 WS 确认 | 否 | SSR seed；服务端预刷新；可选 client in-memory storage |
| Better Auth React | static Convex site URL | session cache/请求 → `/convex/token` → WS 确认 | 否 | session cache；token promise dedupe |
| Better Auth Next | static site/Convex URL | server Cookie → server JWT/getToken → `initialToken` → WS 确认 | 否 | SSR seed、JWT Cookie cache、preload query |

共同特点是，公开的 issuer endpoint、app/client ID 都在 Provider 建立前已知。运行时多租户确实可能需要动态配置，但那是显式高级模式；不应让所有单租户应用默认支付一次 Convex query、一次 React remount 和一次额外 loading phase。

## 对 `convex-logto` 的具体建议

### 可直接借鉴，且不需要改变认证服务边界

1. **默认 API 静态接收公开配置。** `endpoint`、`appId` 不是秘密，默认由 props 或 `VITE_` / `NEXT_PUBLIC_` 环境变量传入；保留 runtime resolver 作为多租户/动态部署的 opt-in。
2. **Provider 只挂载一次。** 配置加载不应通过 React `key` 重建 Logto 与 Convex 全部子树；保持 `useAuth` / `fetchAccessToken` 引用稳定，只有 issuer/app/session/organization 等真正影响 claims 的上下文变化才重新 setAuth。
3. **让 Logto SDK继续做 token 的唯一 owner。** 本库不复制 ID/access/refresh token，不自行实现 storage；bridge 只读 SDK 提供的短期 ID token。
4. **严格实现 Convex 的 cache contract。** 普通请求可返回缓存 ID token；`forceRefreshToken=true` 必须真的绕 cache或触发上游 refresh；并发请求用同一个 in-flight promise 合并。
5. **公开两个启动策略。** 公共页面默认不 `expectAuth`，允许非敏感 UI/query 先出现；登录后专用页面可以文档化 `expectAuth`。升级到兼容 Convex 版本后，可推荐评估 `initialAuthTokenReuse`，减少第二次 Authenticate/query 重跑。
6. **提供可观察性而非无限 loading。** 区分 `config loading`、`IdP session restore`、`token fetch`、`Convex backend confirmation` 与 `refreshing`，为每个网络阶段记录耗时和终止性错误；transient refresh 错误不要立即把用户判为登出。
7. **回调和 redirect 配置静态、精确。** callback path 必须与 Logto 控制台 allowlist 一致；恢复地址必须 same-origin allowlist，不能把未经校验的 `state.returnTo` 直接导航。

### 推荐增加的可选高安全模式

可以单独设计 `convex-logto/nextjs` 或通用 BFF adapter，契约类似：

```text
HttpOnly app session / refresh token
        ↓ same-origin POST, CSRF/origin checked
BFF refreshes Logto and returns only a short Convex-valid ID token
        ↓ memory cache or SSR initialToken
ConvexReactClient WebSocket Authenticate
```

默认安全属性应包括：

- 长期 session/refresh：应用域 `HttpOnly; Secure; SameSite=Lax(or Strict); Path=/`，尽可能使用 `__Host-`；
- callback/refresh/sign-out：同源非 GET mutation、Origin/Fetch Metadata/CSRF 防护；
- 浏览器：只保存短期 JWT到 memory；如提供短 JWT persistence，必须显式 opt-in 并说明 XSS 窗口；
- SSR：只序列化短 JWT，绝不序列化 refresh token；可预取必要的 authenticated query；
- token endpoint：短 TTL、audience 限定 Convex、并发去重、失败分类和服务端 refresh rotation；
- CSP、Trusted Types、依赖治理仍然必要，因为短 JWT 与用户数据最终会进入运行中的 JS。

### 不应做的事

- **不要把 localStorage 机械替换成 `document.cookie`。** 非 `HttpOnly` Cookie同样可被 XSS 读取，还会自动随请求携带，引入 CSRF 面。
- **不要让库同时管理一份 Logto token copy。** 双 storage 会造成轮换、退出、多 tab 和失效状态不一致。
- **不要把 Better Auth cross-domain localStorage envelope 当成安全 Cookie 模式。** 它是跨站兼容方案。
- **不要照搬当前 WorkOS Convex bridge 忽略 `forceRefreshToken` 的行为。** Convex 后端拒绝缓存 JWT时必须能拿到真正的新 token。
- **不要承诺 BFF 能让 JWT 永不进入 JS，同时仍保留浏览器直连 Convex。** 两个目标在当前协议下互斥；只能保护长期凭证，或进一步代理 Convex 数据通道。
- **不要默认首屏查询 `endpoint/appId`。** 只有多租户、运行时 issuer discovery 等真实需求才启用，并应在认证 client 之外缓存/解析，避免 `expectAuth` 依赖环。

## 最终判断

对当前 `convex-logto`，最佳近期默认是：

1. 静态传公开 Logto 配置，消除首屏 config query 与 Provider remount；
2. 继续让 Logto SDK拥有 token，bridge 只做短期 ID token → Convex；
3. 完整 honor 强刷、合并并发 token 请求、保持 Provider identity 稳定；
4. 明确把纯 SPA localStorage 标为便利性/兼容性权衡，而不是最安全行业默认；
5. 另做真正的 BFF/Next.js 高安全模式：长期 refresh/session `HttpOnly`，JS 仅持短 JWT memory/SSR seed。

这与 Convex 生态的真实演进方向一致。纯 SPA 方案接受 JavaScript 可见凭证以换取直连和跨 reload；更强方案利用同源服务器隔离长期会话，但仍只把短 JWT桥接到 Convex WebSocket。
