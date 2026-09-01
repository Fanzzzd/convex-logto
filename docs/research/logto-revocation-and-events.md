# Logto 撤销机制、webhook 事件面与 token TTL

> 调研日期：2026-08-13  
> 范围：self-hosted Logto 的 OAuth 2.0 token revocation（RFC 7009）、Management API 的 session/grant 撤销、RP-initiated logout 对 grant 的影响、webhook 事件全集与 `User.SuspensionStatus.Updated` payload、ID/access/refresh token TTL 的可配置性。为 session component（ticket 08，confidential Traditional Web client 在 Convex 内持有 refresh token）与反应式撤销（ticket 12）提供服务端事实。  
> 来源约束：只使用 Logto 官方源码与官方文档。源码 pin 到 [`logto-io/logto@08aa1e9`](https://github.com/logto-io/logto/tree/08aa1e92860e40873d0c38c4435da7c85d30f43f)（master，`@logto/core` 1.42.0）；OIDC provider 是 Logto 的 fork，pin 到 `packages/core/package.json` 声明的确切 commit [`logto-io/node-oidc-provider@e048347`](https://github.com/logto-io/node-oidc-provider/tree/e04834716e4bfee9f74e8d2e919cae21b2295a8a)。文档引用 docs.logto.io 与 openapi.logto.io（`source.json`）。

## 结论先行

1. **Logto 有标准 RFC 7009 revocation endpoint，confidential client 可以撤销自己的 refresh token。** `features.revocation: { enabled: true }`，路径为 `<endpoint>/oidc/token/revocation`（provider 挂载在 `/oidc`，fork 默认路由 `/token/revocation`）。client 认证方式与 token endpoint 相同：Traditional Web / M2M 是 confidential（`client_secret_basic`），Native / SPA 是 public（`none`）。默认 `allowedPolicy` 只允许撤销**自己 app 的** token：public client 撤别人的 token 会被静默忽略（仍返回 200，防止探测），confidential client 撤别人的 token 直接报 `InvalidRequest`。
2. **撤销一枚 refresh token 会级联撤销整个 grant。** revocation action 对 `RefreshToken`/`AccessToken` 在 `token.destroy()` 之后执行 `revoke(ctx, token.grantId)`：按 grantId 撤销该 grant 下所有 access token、refresh token、authorization code、device code，并（对 refresh token 的场景）销毁 Grant 记录、发出 `grant.revoked`。对 session component 意味着：登出时只需撤销手上那枚 refresh token，一次调用即可终结整条授权链。
3. **RP-initiated logout（`<endpoint>/oidc/session/end`）不撤销带 `offline_access` 的 grant，这是 session component 必须显式撤销的根本原因。** end_session 完整登出时销毁 Session、清 cookie、向注册了 `backchannelLogoutUri` 的 client 发 back-channel logout，但只 revoke `persistsLogout !== true` 的 grant；而 `persistsLogout` 在授权时对任何拿到 `offline_access` 的 client 都被置 `true`（默认 `expiresWithSession = !scopes.has('offline_access')`）。官方文档原话印证："If `offline_access` is granted, grants are not revoked by end-session"，refresh token"remain valid until the earliest of grant expiration, refresh token expiration, or explicit revocation"。
4. **Management API 有完整的服务端「按用户撤销」工具箱（core 1.38.0 起）：** `GET/DELETE /api/users/{userId}/sessions/{sessionId}`（删 session 可带 `revokeGrantsTarget=all|firstParty` 顺带撤 grant）、`GET /api/users/{userId}/grants` + `DELETE /api/users/{userId}/grants/{grantId}`（撤单个 grant 及其 token 链）。更狠的一刀是 `PATCH /api/users/{userId}/is-suspended`：置 `true` 时服务端执行 `signOutUser`，按 userId 撤销该用户**所有** AccessToken、RefreshToken、Session 实例；`DELETE /api/users/{userId}` 同样先 `signOutUser`。`findAccount` 还会对 suspended 用户抛 `InvalidGrant` 兜底，漏网 token 也无法换发。
5. **webhook 没有 session/grant 生命周期事件。** 全部可注册事件为：4 个交互事件（`PostRegister`、`PostSignIn`、`PostSignInAdaptiveMfaTriggered`、`PostResetPassword`）、22 个数据事件（User/Role/Scope/Organization/OrganizationRole/OrganizationScope 的 Created/Deleted/Updated 系）、3 个异常事件（`Identifier.Lockout`、`Message.RateLimited`、`Grant.LimitExceeded`）。没有"token 被撤销""session 结束""用户登出"事件。唯一的 grant 级信号是 1.42.0 新增的 `Grant.LimitExceeded`（仅在超出 app 的 `maxAllowedGrants` 触发旧 grant 逐出时发出，payload 含 `revokedGrantIds`）。OIDC 层的"会话结束通知"通道是 back-channel logout（按 client 配 `backchannelLogoutUri`，Console 有 UI），不是 Logto webhook。
6. **`User.SuspensionStatus.Updated` 的 suspension 状态在 `payload.data.isSuspended`。** 该事件由 `PATCH /users/:userId/is-suspended` 自动注册触发，`data` 字段直接是该请求的响应体（更新后的用户 profile 实体），信封字段为 `hookId`、`event`、`createdAt`（ISO 8601）、`ip`、`userAgent` 加 Management API 上下文（`path`、`method`、`status`、`params`、`matchedRoute`）。签名头仍是 `logto-signature-sha-256`。重要时序事实：挂起用户时**先**服务端撤销全部 token（`signOutUser`），**再**发 webhook，收到事件时撤销已经发生，handler 只需同步 Convex 侧状态。
7. **ID token TTL 是 per-app 可配的，默认 3600 秒，且在该 commit 下没有上下界校验。** `customClientMetadata.idTokenTtl`（zod 为 `z.number().optional()`），通过 Management API `PATCH /api/applications/{id}` 设置；Console UI 不暴露该字段（`packages/console/src` 无引用）。这意味着 session 模式下浏览器短 bearer 的暴露窗口默认 1 小时，可以按需压到分钟级，上界只受自设值约束。
8. **access token TTL：** 有 API resource 时用该 resource 的 `access_token_ttl`（DB 默认 3600 秒，Console 可编辑，schema 无显式范围）；无 resource 的 opaque access token 固定 3600 秒（代码写死）。refresh token TTL 为 `refreshTokenTtlInDays`（zod 限 1–180 天，默认 14 天），confidential client 默认按"70% TTL 已过才轮换"的滑动窗口续期，轮换总时长上限 1 年；Session TTL 默认 14 天，租户级可通过 `PATCH /api/configs/oidc/session` 配 1 秒–1 年；Grant TTL 固定 180 天。

## 调研版本边界

| 对象 | 快照 | 备注 |
|---|---|---|
| Logto core / schemas / console | [`08aa1e9`](https://github.com/logto-io/logto/tree/08aa1e92860e40873d0c38c4435da7c85d30f43f)，`@logto/core` `package.json` version `1.42.0` | master HEAD（调研日）。版本号引用以 `packages/core/CHANGELOG.md` 的发布段落为准。 |
| oidc-provider（Logto fork） | [`e048347`](https://github.com/logto-io/node-oidc-provider/tree/e04834716e4bfee9f74e8d2e919cae21b2295a8a) | `packages/core/package.json` 以 `github:logto-io/node-oidc-provider#e048347…` 精确锁定，行为即部署行为。 |
| Management API 参考 | [openapi.logto.io](https://openapi.logto.io/)（[`source.json`](https://openapi.logto.io/source.json)，调研日抓取） | 用于确认端点已发布及 operationId。 |
| 功能可用版本 | session/grant 管理 API、OIDC session TTL 配置、`maxAllowedGrants`：**1.38.0**；Account API `isCurrent`：**1.40.0**；`Grant.LimitExceeded` webhook：**1.42.0** | 来自 `packages/core/CHANGELOG.md`。self-host 用户需 ≥ 对应版本。 |

## 1. 撤销

### 1.1 RFC 7009 revocation endpoint

[`packages/core/src/oidc/init.ts:207-218`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L207-L218) 启用的 features：

```ts
features: {
  userinfo: { enabled: true },
  revocation: { enabled: true },
  introspection: { enabled: true },
  ...
  backchannelLogout: { enabled: true },
```

- **路径**：provider 挂载在 `/oidc`（[`Tenant.ts:149`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/tenants/Tenant.ts#L149)：`app.use(mount('/oidc', provider))`），fork 默认路由 `revocation: '/token/revocation'`、`end_session: '/session/end'`（fork `lib/helpers/defaults.js:2678-2683`）。即 `POST <endpoint>/oidc/token/revocation`；discovery 文档（`<endpoint>/oidc/.well-known/openid-configuration`）会公布 `revocation_endpoint`。
- **client 认证**：与 token endpoint 相同。[`packages/core/src/oidc/utils.ts:45-52`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/utils.ts#L45-L52)：Traditional Web 与 M2M 为 `client_secret_basic`（confidential），Native/SPA 为 `none`（public）。所以我们的 Traditional Web session component 用 app secret 做 Basic 认证即可调用。
- **可撤销类型**：`AccessToken`、`ClientCredentials`、`RefreshToken`（fork `lib/actions/revocation.js:12`）。ID token 不是可撤销对象，它是无状态 JWT，签发后只能等 `exp`。
- **归属校验（默认 `allowedPolicy`，fork `lib/helpers/defaults.js` `revocationAllowedPolicy`）**：token 属于调用方 client 时放行；不属于时，public client 返回 `false`（不撤销但响应 200，"disallow guessing valid tokens"），confidential client 直接 `throw new errors.InvalidRequest('client is not authorized to revoke the presented token')`。**结论：component 只能撤销自己 app 的 token，不能代替其他 app 撤销。**

### 1.2 撤销 refresh token = 撤销整个 grant

fork `lib/actions/revocation.js:74-78`：

```js
await token.destroy();
if (token.kind === 'RefreshToken' || token.kind === 'AccessToken') {
  await revoke(ctx, token.grantId);
}
```

`revoke()`（fork `lib/helpers/revoke.js`）按 grantId 撤销 grant 下的 AccessToken、RefreshToken、AuthorizationCode、DeviceCode、CIBA 请求；`revokeGrantPolicy` 默认在"revocation 路由 + 被撤对象是 AccessToken"时保留 Grant 记录（保住 consent，避免下次重新授权弹确认），其余情况（含撤 refresh token）连 Grant 一起 `destroy` 并发出 `grant.revoked` 事件。Logto core 未覆写 `revokeGrantPolicy` 与 `expiresWithSession`（在 `packages/core/src` 中无同名配置项）。

### 1.3 Management API：按用户撤销 session / grant

均确认存在于 pinned 源码并已发布到 [openapi.logto.io](https://openapi.logto.io/)（operationId 摘自 `source.json`）；self-host 需 core ≥ 1.38.0：

| 端点 | operationId | 行为（源码依据） |
|---|---|---|
| `GET /api/users/{userId}/sessions` | `ListUserSessions` | 列活跃 session（含 `payload.uid`、`clientId`、`expiresAt`、`lastSubmission` 设备/IP 上下文）。[`admin-user/session.ts:22-42`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/admin-user/session.ts#L22-L42) |
| `DELETE /api/users/{userId}/sessions/{sessionId}` | `DeleteUserSession` | 按 session `uid` 销毁 Session；可选 `?revokeGrantsTarget=all\|firstParty` 先撤销该 session 关联的 grant，再 `session.destroy()`。**不传 `revokeGrantsTarget` 时仅销毁 session，带 `offline_access` 的 refresh token 依旧可用**（与 1.4 的 logout 语义一致）。[`admin-user/session.ts:67-107`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/admin-user/session.ts#L67-L107) |
| `GET /api/users/{userId}/grants` | `ListUserGrants` | 列活跃 grant，可 `?appType=firstParty\|thirdParty` 过滤。[`admin-user/grants.ts:27-51`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/admin-user/grants.ts#L27-L51) |
| `DELETE /api/users/{userId}/grants/{grantId}` | `DeleteUserGrant` | `revokeUserGrantById`（grant + token 链）并清理 session 上对应的 authorization 记录。[`admin-user/grants.ts:53-79`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/admin-user/grants.ts#L53-L79) |
| `PATCH /api/users/{userId}/is-suspended` | 无 | `isSuspended: true` 时执行 `signOutUser(user.id)`。[`admin-user/basics.ts:442-470`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/admin-user/basics.ts#L442-L470) |
| `DELETE /api/users/{userId}` | 无 | 删除前 best-effort `signOutUser`（撤销语句超时不阻塞删除，残留实例因账号无法解析而失效）。[`admin-user/basics.ts:472-499`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/admin-user/basics.ts#L472-L499) |

`signOutUser`（[`libraries/user.ts:229-236`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/libraries/user.ts#L229-L236)）：

```ts
const signOutUser = async (userId: string) => {
  await Promise.all([
    revokeInstanceByUserId('AccessToken', userId),
    revokeInstanceByUserId('RefreshToken', userId),
    revokeInstanceByUserId('Session', userId),
    oidcSessionExtensions.deleteByAccountId(userId),
  ]);
};
```

兜底：`findAccount` 对 suspended 用户抛 `InvalidGrant('user is suspended')`（[`init.ts:422-432`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L422-L432)，注释原话"Suspension revokes the user's sessions and tokens; reject here as well so any token that survives a partial revocation still cannot be used"）。文档表述一致：挂起后用户"won't be able to obtain a new access token after the current one expires"（[Manage users](https://docs.logto.io/user-management/manage-users)）。

另有终端用户自助面（Account API，1.38.0 起）：`GET /api/my-account/sessions`（1.40.0 起带 `isCurrent`）、`DELETE /api/my-account/sessions/{sessionId}`（同样支持 `revokeGrantsTarget`），受 `urn:logto:scope:sessions` scope 与 account center `session` 权限门控，与 component 关系不大，但说明"设备管理"类 UI 可以不经 Management API 实现。

### 1.4 RP-initiated logout 对 grant 的影响

fork `lib/actions/end_session.js:157-177`（完整登出分支）：

```js
if (params.logout) {
  if (session.authorizations) {
    await Promise.all(
      Object.entries(session.authorizations).map(async ([clientId, { grantId }]) => {
        // Drop the grants without offline_access
        // Note: tokens that don't get dropped due to offline_access having being added
        // later will still not work, as such they will be orphaned until their TTL hits
        if (grantId && !session.authorizationFor(clientId).persistsLogout) {
          await revoke(ctx, grantId);
        }
      }),
    );
  }
  await session.destroy();
  ctx.cookies.set(ctx.oidc.provider.cookieName('session'), null, opts);
}
```

`persistsLogout` 的来源（fork `lib/helpers/process_response_types.js:47-52,117-121`）：授权成功签发 code / opaque token 时，若 `expiresWithSession(ctx, token)` 为假则置 `persistsLogout = true`；默认 `expiresWithSession = !code.scopes.has('offline_access')`（fork `lib/helpers/defaults.js:258-260`）。即：

- **要了 `offline_access` 的 client（Logto 各 SDK 默认都要）：logout 后 grant 与 refresh token 原样存活**，直到 grant 过期（180 天）、refresh token 过期或被显式撤销。官方文档同义确认（[Sign-out](https://docs.logto.io/end-user-flows/sign-out)）。
- 没要 `offline_access` 的 client：logout 时 grant 被 revoke。注意 Logto 的 `alwaysIssueRefreshToken`（web app 专用逃生门，[`init.ts:258-267`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L258-L267)）发的 refresh token 因 scope 里没有 `offline_access` 而是 session-bound 的，logout 即失效。
- 单 client 登出分支（`params.logout` 为假）同理，只处理发起 client 的 grant。
- back-channel logout 在 revoke 之前发出，只发给配置了 `backchannelLogoutUri` 的 client。

**对 session component 的直接结论：`signOut` 不能只跳 `end_session_endpoint`，必须同时（先）调 `POST /oidc/token/revocation` 撤销自己持有的 refresh token，否则 Convex 里那份 refresh token 在 Logto 侧仍然有效。**

## 2. webhook 事件面

### 2.1 事件全集（pinned 源码）

[`packages/schemas/src/foundations/jsonb-types/hooks.ts:59-89`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/foundations/jsonb-types/hooks.ts#L59-L89) 的 `hookEvents` 是可注册事件的封闭枚举：

- 交互：`PostRegister`、`PostSignIn`、`PostSignInAdaptiveMfaTriggered`、`PostResetPassword`
- 数据：`User.{Created,Deleted,Data.Updated,SuspensionStatus.Updated}`、`Role.*`、`Scope.*`、`Organization.*`、`OrganizationRole.*`、`OrganizationScope.*`（共 22 个）
- 异常：`Identifier.Lockout`、`Message.RateLimited`、`Grant.LimitExceeded`

**不存在** `Session.*`、`Grant.Revoked`、token 撤销或登出类事件；[官方 webhook 事件文档](https://docs.logto.io/developers/webhooks/webhooks-events)列表与源码一致。三点补充：

1. `Grant.LimitExceeded`（1.42.0，异常事件）：授权成功导致活跃 grant 数超过该 app `customClientMetadata.maxAllowedGrants` 而逐出旧 grant 时触发；`data` 为 `{ userId, applicationId?, cimdClientId?, revokedGrantIds, maxAllowedGrants, preRevocationActiveGrantCount }`（[`hook.ts:116-130`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/types/hook.ts#L116-L130)）。这是目前唯一带 `revokedGrantIds` 的事件，但只覆盖"超额逐出"一种撤销场景，不能当通用撤销信号。
2. OIDC 层的会话结束通知是 **back-channel logout**（`features.backchannelLogout` 已启用，per-app 在 Console"Backchannel logout"或 Management API 配 `backchannelLogoutUri`）。它是发给各 RP 的 logout token（JWT），不是 Logto webhook 体系的一部分；若 component 要"用户在别处登出→Convex 反应"，这是唯一的推送通道，否则只能轮询 Management API sessions/grants。
3. 交互事件 `PostSignIn` 的 payload 有 `sessionId`，但它是 `interactionDetails.jti`（交互事务 id，[`koa-experience-interaction-hooks.ts:59`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/routes/experience/middleware/koa-experience-interaction-hooks.ts#L59)），**不是** `/users/{userId}/sessions` 里的 session `uid`，不能拿它直接 join 会话管理 API（诚实标注：两者是否存在稳定推导关系未验证，按"不可 join"设计最稳）。

### 2.2 `User.SuspensionStatus.Updated` 的 payload

触发链（全部 pinned 源码）：

1. 路由注册表 [`hooks.ts:136`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/foundations/jsonb-types/hooks.ts#L136)：`'PATCH /users/:userId/is-suspended': 'User.SuspensionStatus.Updated'`。
2. 中间件在请求成功后取 `data: ctx.response.body`（[`context-manager.ts` `getRegisteredHookEventContext`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/libraries/hook/context-manager.ts)），即该 PATCH 的响应体，更新后的用户 profile 实体。
3. 信封类型 `DataHookEventPayload`（[`hook.ts:93-102`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/types/hook.ts#L93-L102)）：`{ event, createdAt (ISO 8601), hookId, ip?, userAgent?, data?, path, method, status, params?, matchedRoute? }`。

**所以 suspension 布尔读 `payload.data.isSuspended`**；[官方 payload 文档](https://docs.logto.io/developers/webhooks/webhooks-request)的 `UserEntity` 字段表同样列出 `isSuspended`。签名头 `logto-signature-sha-256`（HMAC，对 raw body），与本仓库已接入的验签方式一致。

时序：`PATCH is-suspended` 的 handler 先 `updateUserById` + `signOutUser`（撤销全部 token），响应返回后才异步发 webhook（`void trySafe(hooks.triggerDataHooks(...))`，[`koa-management-api-hooks.ts:51-55`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/middleware/koa-management-api-hooks.ts#L51-L55)）。**ticket 12 的反应式撤销收到该事件时，Logto 侧撤销已完成，Convex 侧只需清 session 表/标记用户**；webhook 失败最多重试 3 次，handler 仍需幂等（沿用 auth-storage 调研的防重放结论）。

## 3. token TTL

### 3.1 ID token：per-app 可配，默认 3600 秒，无范围校验

- 默认值：`customClientMetadataDefault.idTokenTtl = inSeconds.oneHour`（[`consts/oidc.ts:14-18`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/consts/oidc.ts#L14-L18)）。
- 生效点：`ttl.IdToken = client.metadata().idTokenTtl ?? 3600`（[`init.ts:481-485`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L481-L485)）。
- 校验：`customClientMetadataGuard` 中 `idTokenTtl: z.number().optional()`，**该 commit 下无最小/最大值约束**（[`oidc-module.ts:107-118`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/foundations/jsonb-types/oidc-module.ts#L107-L118)）。
- 配置入口：Management API `PATCH /api/applications/{id}` 的 `customClientMetadata`；**Console UI 不暴露该字段**（`packages/console/src` 全量 grep 无 `idTokenTtl` 引用）。
- 对设计的意义：session 模式下浏览器只持 ID token 时，暴露窗口默认 1 小时；component 文档可以指导用户把目标 app 的 `idTokenTtl` 压到例如 300–900 秒。诚实标注：Logto Cloud 是否额外限制该字段未验证（本调研只覆盖 self-host 源码路径）；过短的 TTL 会放大换发频率，需与 Convex 的 token 刷新节奏联动评估。

### 3.2 access token：per-resource 可配，默认 3600 秒

- 有 resource（audience）时：`token.resourceServer.accessTokenTTL ?? 3600`，值来自 API resource 的 `access_token_ttl` 列，DB 默认 3600（[`resources.sql`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/tables/resources.sql)，`bigint not null default(3600)`）。Console 的 API resource 设置页可编辑（必填数字，表单未设 min/max；schema 层同样无范围约束）。
- 无 resource 的 opaque access token：代码写死 3600 秒（[`init.ts:504-510`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L504-L510)），不可配。

### 3.3 refresh token / session / grant（撤销窗口的另一半）

| 对象 | 默认 | 可配范围 | 来源 |
|---|---|---|---|
| refresh token TTL | 14 天 | `refreshTokenTtlInDays`：zod `int().min(1).max(180)`，per-app | [`oidc-module.ts:111`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/foundations/jsonb-types/oidc-module.ts#L111)、[`init.ts:486-503`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L486-L503) |
| refresh token 轮换 | 开启 | confidential：TTL 过 70% 才轮换（滑动续期），总轮换上限 1 年；public SPA：每次都轮换但**继承剩余 TTL**（不滑动）；仅 Traditional Web 可关闭 | [`oidc/defaults.ts`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/defaults.ts)、[`init.ts:517-528`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L517-L528) |
| Session TTL | 14 天 | 租户级 `PATCH /api/configs/oidc/session`，`ttl` zod `int().min(1).max(31_536_000)`（1 秒–1 年），1.38.0 起 | [`logto-config/index.ts:66-68`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/schemas/src/types/logto-config/index.ts#L66-L68)、[`init.ts:513`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L513) |
| Grant TTL | 180 天（写死） | 不可配（注释："Set this to the longest allowed duration of the refresh token"） | [`init.ts:515`](https://github.com/logto-io/logto/blob/08aa1e92860e40873d0c38c4435da7c85d30f43f/packages/core/src/oidc/init.ts#L515) |

## 4. 对 session component 设计的直接推论

1. **登出路径必须是"revocation 先行"**：component 的 `signOut` 先用 client secret 调 `POST /oidc/token/revocation`（body `token=<refresh_token>`），一次调用级联清掉整个 grant；然后才（可选地）把浏览器送去 `end_session_endpoint` 清 Logto SSO cookie。只做后者会把有效 refresh token 留在 Convex 表里且 Logto 侧仍可用。
2. **服务端强制下线有三档**：撤单 grant（`DELETE /users/{userId}/grants/{grantId}`）→ 撤单 session 并连带 grant（`DELETE /users/{userId}/sessions/{sessionId}?revokeGrantsTarget=firstParty`）→ 全量（`PATCH is-suspended` 或直接对每枚已存 refresh token 调 revocation endpoint）。component 自己持有 token，第三档不依赖 Management API 权限即可实现。
3. **反应式撤销（ticket 12）只能依赖现有事件面**：`User.SuspensionStatus.Updated`（读 `data.isSuspended`）+ `User.Deleted` 已足够覆盖"管理员封禁/删号"；"用户在其他设备登出"没有 webhook，可选方案是给 app 配 `backchannelLogoutUri` 指向 Convex httpAction（logout token 需按 OIDC Back-Channel Logout 1.0 验签），或接受"下次 refresh 失败时清理"的惰性模型。
4. **浏览器暴露窗口的预算**：短 bearer = ID token，默认 3600 秒、per-app 可压缩且无下界校验；refresh token 永不出服务端。文档应写明 `idTokenTtl` 只能经 Management API 设置（Console 无 UI）。

## 尚未验证 / 已知不确定

- Logto **Cloud** 对 `idTokenTtl`、`accessTokenTtl` 是否有额外的平台侧限制未验证（本调研全部基于 self-host 源码）。
- `PostSignIn.sessionId`（interaction jti）与 OIDC Session `uid` 之间是否存在可推导关系未验证；按不可 join 设计。
- session/grant 管理 API 在 1.38.0 之前的 Logto 版本不存在；面向老版本 self-host 的兼容策略需要在 component 文档中显式声明最低版本。
- fork 与 upstream node-oidc-provider 在 revocation/end_session 语义上基本一致（`persistsLogout`、grant 级联均为 upstream 既有行为），但本文引用一律以 fork pinned commit 为准，未逐行 diff upstream。
