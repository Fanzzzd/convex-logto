# Logto refresh token rotation 与 reuse-detection 实况（自托管当前 release）

> 调研日期：2026-08-13  
> 范围：自托管 Logto 对 (a) SPA public client（PKCE）与 (b) Traditional Web confidential client 的 refresh token 轮换、TTL 与复用检测行为；M2M/Protected 不在结论范围内。  
> 来源约束：只使用 Logto 官方源码（`logto-io/logto`、`logto-io/node-oidc-provider` fork）与官方文档 docs.logto.io；所有源码链接固定到 tag `v1.42.0` 或具体 commit。  
> 目的：为 `convex-logto` 的 bridge 模式风险表述（ticket 01 动机 1）和 session component 的服务端 refresh 契约（ticket 08，动机 2）提供可引用的事实。

## 结论先行

1. **生效的 `rotateRefreshToken` 是 Logto 自己写的函数，不是 node-oidc-provider 的开箱默认，但语义上等价于「per-app 开关 + node-oidc-provider 默认策略」。** Logto 在 provider 配置里传入一个函数：若应用的 `customClientMetadata.rotateRefreshToken` 被显式设为 `false` 则永不轮换；否则委托给 Logto 本地复刻的 node-oidc-provider 默认策略。该开关默认 `true`。
2. **两类 client 的实际轮换行为不同。** 默认策略下：**public client（SPA、Native，`token_endpoint_auth_method: none`）只要 refresh token 不是 sender-constrained，每次 refresh 都轮换**；**confidential client（Traditional Web，`client_secret_basic`）只在 token 已消耗 ≥70% TTL 时才轮换**。另有一条全局上限：refresh token 链 `totalLifetime` 达到 1 年后不再轮换，当前 token 的过期时间即为最终过期时间。
3. **SPA 的 refresh token 是「绝对生命周期」，Traditional Web / Native 是「轮换时重置的滑动生命周期」。** TTL 函数里有一个专门针对 `application_type: web` + `clientAuthMethod: none`（即 SPA）的前置检查：轮换出的新 token 继承旧 token 的 `remainingTTL`，即 SPA 整条 token 链从首次签发起最多活 `refreshTokenTtlInDays`（默认 14 天）。Native 与 confidential client 轮换时新 token 拿满额 TTL；但**不轮换的 refresh 请求不会延长现有 token 的过期时间**。
4. **TTL 默认 14 天，per-app 可配 1–180 天（Console 与 Management API 均可）。** 另有两条独立上限：Grant TTL 硬编码 180 天（refresh 处理器不续期 grant，grant 过期后 refresh 直接失败）；不带 `offline_access` 签发的 refresh token 绑定用户 session（session 默认 14 天）。
5. **复用检测：已被轮换（consumed）的 refresh token 再次被使用时，Logto 销毁该 token 并吊销整个 grant（整条 token 族），返回 `invalid_grant`。** 这是 node-oidc-provider 的语义，Logto 复制的 grant handler 原样保留，`revokeGrantPolicy` 未被覆盖（默认吊销 grant 本体）。**没有任何并发宽限窗口**：合法客户端自己并发 refresh 撞上刚被 consume 的旧 token，同样会核掉整个 token 族。
6. **文档与源码总体一致，但有三处值得记录：** Console 的 TTL 提示文案对 SPA 不成立（说「token 请求会把 TTL 延长到该值」，而 SPA 明确不延长）；`@logto/schemas` 里的代码注释过时（称 rotation 开关「只有 traditional web 可关」，实际任何应用类型都能关且服务端会尊重）；**复用检测「吊销整族」的行为在 Logto 产品文档里没有描述**，只出现在其 node-oidc-provider fork 的 README 与源码中。
7. **对 convex-logto 的直接推论：**（动机 1）默认配置下 SPA 的被盗 refresh token 不能「长期静默滥用」——攻击者每用一次就轮换，受害者客户端下一次 refresh 即触发整族吊销，且整条链有绝对 TTL（默认 14 天）封顶；风险表述应降级为「在受害者下次刷新或绝对 TTL 到期之前的窗口」。（动机 2）Logto 对 confidential client **确实会轮换**（≥70% TTL 时），session component 必须把「token 响应里出现新 `refresh_token` 就原子持久化」和「单飞（single-flight）refresh」写进契约，否则并发刷新会触发整族吊销。

## 调研版本边界

| 对象 | 快照 | 备注 |
|---|---|---|
| `logto-io/logto` release | tag [`v1.42.0`](https://github.com/logto-io/logto/tree/v1.42.0)（2026-07-30 发布，调研日最新 release） | 本文源码行号均指向该 tag |
| `logto-io/logto` master | commit [`08aa1e9`](https://github.com/logto-io/logto/tree/08aa1e92860e40873d0c38c4435da7c85d30f43f)（2026-08-12） | 已 diff 验证：rotation / TTL / reuse 相关逻辑与 v1.42.0 完全一致，仅 CIMD 与 organization scope 处理有无关差异 |
| oidc-provider 依赖 | fork [`logto-io/node-oidc-provider@d2f08cf`](https://github.com/logto-io/node-oidc-provider/tree/d2f08cf55fd683c18095f6b226818d4f761c0c41)，包版本 `9.9.1` | 见 [`packages/core/package.json`](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/package.json)（`"oidc-provider": "github:logto-io/node-oidc-provider#d2f08cf..."`） |
| docs.logto.io | 2026-08-13 抓取 | 主要页面：[Application data structure](https://docs.logto.io/integrate-logto/application-data-structure) |

一个容易踩错的前提：**Logto 并不使用 oidc-provider 自带的 `refresh_token` grant 处理器**。它在初始化后用 [`registerGrants`](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/index.ts#L32-L37) 以自己的 [`packages/core/src/oidc/grants/refresh-token.ts`](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/refresh-token.ts) 覆盖默认实现。该文件头注释声明它是 fork `v9` 分支（commit `d60ae9b`，与 upstream `v9.9.1` tag 相同）的逐行拷贝，仅为 organization token（RFC 0001）做了标注过的增改（[头注释 L1-L31](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/refresh-token.ts#L1-L31)）。经比对，consumed 检查与轮换块与 fork 原文一致，因此下文引用 Logto 拷贝为准、fork 原文为旁证。

## 1. 生效的 `rotateRefreshToken` 配置链

Logto 传给 provider 的是一个函数（[`init.ts` L458-L469](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L458-L469)）：

```ts
rotateRefreshToken: (ctx) => {
  const { Client: client } = ctx.oidc.entities;
  // Directly return false only when `rotateRefreshToken` has been explicitly set to `false`.
  if (!(client?.metadata().rotateRefreshToken ?? customClientMetadataDefault.rotateRefreshToken)) {
    return false;
  }
  return defaults.rotateRefreshToken(ctx);
},
```

三层组成：

1. **per-app 开关**：`customClientMetadata.rotateRefreshToken`，布尔，默认 `true`（[`customClientMetadataDefault`，schemas L14-L18](https://github.com/logto-io/logto/blob/v1.42.0/packages/schemas/src/consts/oidc.ts#L14-L18)）。任何应用类型设为 `false` 都会让该应用**完全不轮换**——代码对 client 类型无区分。
2. **Logto 本地复刻的默认策略** [`packages/core/src/oidc/defaults.ts` L23-L41](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/defaults.ts#L23-L41)：
   - `totalLifetime() >= 365.25 天` → 不再轮换（轮换 1 年上限，此后 TTL 定格）；
   - `clientAuthMethod === 'none'` 且 token 非 sender-constrained → **轮换（public client 每次 refresh 都轮换）**；
   - 其余情况 → 仅当 `ttlPercentagePassed() >= 70` 时轮换。
3. 该复刻与 fork 文档中的默认值逐行一致（[fork `docs/README.md` `rotateRefreshToken` 一节](https://github.com/logto-io/node-oidc-provider/blob/d2f08cf55fd683c18095f6b226818d4f761c0c41/docs/README.md#rotaterefreshtoken)），所以「Logto 用的是 node-oidc-provider 默认策略 + 一个 per-app 总开关」这个心智模型是准确的。

client 类型到 OIDC 元数据的映射在 [`getConstantClientMetadata`，`utils.ts` L33-L62](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/utils.ts#L33-L62)：

| Logto 应用类型 | `application_type` | `token_endpoint_auth_method` | 分类 |
|---|---|---|---|
| SPA | `web` | `none` | public |
| Native | `native` | `none` | public |
| Traditional Web | `web` | `client_secret_basic` | confidential |
| M2M | `web` | `client_secret_basic` | confidential（无用户 refresh token 场景） |

PKCE 对所有非 `client_secret_basic` 客户端强制启用（[`init.ts` L470-L474](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L470-L474)）。refresh token 是否签发由 [`issueRefreshToken`，`init.ts` L229-L238](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L229-L238) 决定：grant type 允许，且（scope 含 `offline_access`，或 `application_type: web` 应用开启了 `alwaysIssueRefreshToken`）。

**对两类 client 的求值结果（默认配置）：**

- **SPA / Native（public, PKCE）**：每次 refresh 轮换，直到链存在满 1 年（SPA 实际到不了，见下节）。
- **Traditional Web（confidential）**：仅当当前 refresh token 已过 70% TTL 时轮换；未过 70% 的 refresh 返回同一个 refresh token。

## 2. TTL：绝对与滑动、默认值与 per-app 配置

TTL 函数（[`init.ts` L427-L444](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L427-L444)）先执行 Logto 复刻的 oidc-provider 前置检查（[`defaults.ts` L8-L20](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/defaults.ts#L8-L20)）：

```ts
if (
  ctx.oidc.entities.RotatedRefreshToken &&
  client.applicationType === 'web' &&
  client.clientAuthMethod === 'none' &&
  !token.isSenderConstrained()
) {
  // Non-Sender Constrained SPA RefreshTokens do not have infinite expiration through rotation
  return ctx.oidc.entities.RotatedRefreshToken.remainingTTL;
}
```

命中该分支的只有 **SPA**（`web` + `none`）：轮换出的新 token 继承旧 token 的剩余 TTL。未命中（Native、confidential、或非轮换场景的首发 token）则取 `refreshTokenTtlInDays * 86400`，per-app 未配置时取默认 14 天；还有一个已弃用的秒级 `refreshTokenTtl` 字段作兜底（[`init.ts` L435-L443](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L427-L444)，弃用标注见 [`oidc-module.ts` L64-L67](https://github.com/logto-io/logto/blob/v1.42.0/packages/schemas/src/foundations/jsonb-types/oidc-module.ts#L64-L67)）。

因此：

| 维度 | SPA | Native | Traditional Web |
|---|---|---|---|
| 轮换频率（默认） | 每次 refresh | 每次 refresh | ≥70% TTL 时 |
| 轮换后新 token TTL | 继承剩余 TTL（**绝对生命周期**） | 满额重置（滑动） | 满额重置（滑动） |
| 不轮换的 refresh 是否延长 TTL | 否 | 否（每次都轮换，不适用） | **否**（同一 token 的 `exp` 不变，handler 不重存旧 token） |
| 链的实际上限 | 首发起 `refreshTokenTtlInDays`（默认 14 天） | min(滑动续命, 轮换 1 年上限, Grant 180 天) | min(滑动续命, 轮换 1 年上限, Grant 180 天) |

**per-app 可配性**：`refreshTokenTtlInDays` 为整数 1–180（[zod guard，`oidc-module.ts` L107-L118](https://github.com/logto-io/logto/blob/v1.42.0/packages/schemas/src/foundations/jsonb-types/oidc-module.ts#L107-L118)）。Console 对非 M2M/Protected 的所有应用（Native、SPA、Traditional）展示「Rotate refresh token」开关与「Refresh token TTL in days」输入框（渲染条件 [`index.tsx` L252-L254](https://github.com/logto-io/logto/blob/v1.42.0/packages/console/src/pages/ApplicationDetails/ApplicationDetailsContent/index.tsx#L252-L254)，表单 [`RefreshTokenSettings.tsx` L43-L96](https://github.com/logto-io/logto/blob/v1.42.0/packages/console/src/pages/ApplicationDetails/ApplicationDetailsContent/RefreshTokenSettings.tsx#L43-L96)）；`alwaysIssueRefreshToken` 只对 Traditional + SPA 展示。Management API 走同一 `customClientMetadataGuard` 校验（[`validateCustomClientMetadata`，`utils.ts` L110-L119](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/utils.ts#L110-L119)）。

**两条独立上限**：

- **Grant TTL 硬编码 180 天**（[`init.ts` L454-L456](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L454-L456)，注释「Set this to the longest allowed duration of the refresh token」）。refresh 处理器每次都 `validateGrant`，grant 过期直接 `invalid_grant: grant is expired`（[fork `grant_common.js` L41-L59](https://github.com/logto-io/node-oidc-provider/blob/d2f08cf55fd683c18095f6b226818d4f761c0c41/lib/helpers/grant_common.js#L41-L59)）；refresh 处理器中没有任何对 grant 的重存/续期。官方文档同样明确「grant 过期后即便 refresh token 本身仍有效，refresh 请求也会失败」（[docs：Refresh token TTL 一节](https://docs.logto.io/integrate-logto/application-data-structure#refresh-token-time-to-live-ttl-in-days)）。*不确定*：重新走一次交互式登录/同意是否会重存同一 grant 并刷新其 `exp`，本次未追踪该路径；对「单次登录后纯靠 refresh 续命」的场景，180 天是绝对上限这一点是确定的。
- **session 绑定**：不带 `offline_access` 签发的 refresh token 带 `expiresWithSession`，随用户 session（默认 14 天，租户 DB 配置可改，[`init.ts` L454](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/init.ts#L454)、[`env-set/oidc.ts` L23,L39](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/env-set/oidc.ts#L23-L39)）失效；官方文档明确此行为并建议加 `offline_access`（[docs 同页](https://docs.logto.io/integrate-logto/application-data-structure#refresh-token-time-to-live-ttl-in-days)）。Logto 官方 SPA SDK 默认总是请求 `offline_access`（见本目录 `auth-storage-and-bootstrap.md` §2.1），所以 SPA 场景一般不受此限。

## 3. 复用检测：轮换开启时复用旧 token 会发生什么

Logto 拷贝的 grant handler（[`grants/refresh-token.ts` L223-L226](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/refresh-token.ts#L223-L226)，与 [fork `refresh_token.js` L121-L127](https://github.com/logto-io/node-oidc-provider/blob/d2f08cf55fd683c18095f6b226818d4f761c0c41/lib/actions/grants/refresh_token.js#L121-L127) 相同）：

```ts
if (refreshToken.consumed) {
  await Promise.all([refreshToken.destroy(), revoke(ctx, refreshToken.grantId)]);
  throw new InvalidGrant('refresh token already used');
}
```

- 轮换发生时旧 token 被 `consume()` 标记（[L250-L255](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/refresh-token.ts#L250-L255)）；新 token 携带 `rotations + 1` 计数（[L270](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/refresh-token.ts#L257-L278)）。
- `revoke(ctx, grantId)` 按 grantId 吊销 **AccessToken、RefreshToken、AuthorizationCode（以及 DeviceCode/CIBA）全部实例**，并按 `revokeGrantPolicy` 销毁 Grant 本体（[fork `revoke.js`](https://github.com/logto-io/node-oidc-provider/blob/d2f08cf55fd683c18095f6b226818d4f761c0c41/lib/helpers/revoke.js)）。`revokeGrantPolicy` 默认在此路径返回 `true`（[fork `defaults.js` L508-L513](https://github.com/logto-io/node-oidc-provider/blob/d2f08cf55fd683c18095f6b226818d4f761c0c41/lib/helpers/defaults.js#L508-L513)），Logto 的 `init.ts` 未覆盖它（全文无 `revokeGrantPolicy`）。**即：整条 token 族连同 grant 一起被吊销，Logto 没有做任何弱化或加强。** fork 文档的表述一致：「when a consumed refresh token is encountered an error shall be returned and the whole token chain (grant) is revoked」（[fork README](https://github.com/logto-io/node-oidc-provider/blob/d2f08cf55fd683c18095f6b226818d4f761c0c41/docs/README.md#rotaterefreshtoken)）。

四个边界事实：

1. **过期检查先于 consumed 检查**（[L160-L161](https://github.com/logto-io/logto/blob/v1.42.0/packages/core/src/oidc/grants/refresh-token.ts#L148-L161)）：重放一个已过期的旧 token 只得到普通 `invalid_grant`，不触发整族吊销。
2. **没有并发宽限窗口**：`consume()` 即时生效，旧 token 在响应尚未送达客户端时就已「已用」。合法客户端并发发起两次 refresh、或持久化新 token 失败后重试旧 token，都会触发整族吊销。上游没有 Auth0 式的 rotation reuse interval 概念。
3. **整族吊销不销毁 Logto 的用户 session**（`revoke.js` 不触碰 Session 实例）：浏览器里仍有活 session cookie 的用户可以无感重新走一次授权码流程拿到新 grant；对纯服务端持有 refresh token 的场景则必须让用户重新登录。
4. **已签发的 JWT 无法召回**：整族吊销销毁的是服务端记录；已发出的 ID token / JWT 格式 access token 在其自身 `exp` 前仍可被离线验签方（如 Convex）接受。

## 4. 官方文档 vs 源码

[docs.logto.io Application data structure](https://docs.logto.io/integrate-logto/application-data-structure)（2026-08-13 抓取）当前对 rotation 的描述**与源码高度一致**，且明确到罕见的程度：public client 每次请求轮换、其余 ≥70% 才轮换、1 年轮换上限、SPA「rotation issues a new refresh token but does not extend the refresh token's lifetime. The new refresh token inherits the remaining TTL of the previous refresh token」、grant TTL 180 天为链的绝对上限、无 `offline_access` 时绑定 session。TTL 一节标注「Availability: Native app, Traditional web, SPA; Default: 14 days; Maximum: 180 days」，与 Console 渲染条件和 zod guard 完全对应。

发现的不一致（按影响排序）：

1. **复用检测行为在产品文档缺失。** 「已用 token 再现 → 吊销整个 grant/token 族」只见于 fork README 与源码，Application data structure 页未提及。*不确定*：docs.logto.io 其他页面是否有描述——本次只系统检查了该主页面与其链接节，未做全站遍历。
2. **Console 提示文案对 SPA 不成立。** `refresh_token_ttl_tip`：「Token requests will extend the TTL of the refresh token to this value.」（[phrases L67-L69](https://github.com/logto-io/logto/blob/v1.42.0/packages/phrases/src/locales/en/translation/admin-console/application-details.ts#L67-L69)）。对 SPA，TTL 从不延长（§2）；docs 网页版在同一句后补了 SPA 例外说明，Console UI 没有。另外该句对 confidential client 也不精确：TTL 只在**轮换时**（≥70%）重置，普通 token 请求不延长现有 token 的 `exp`。
3. **`@logto/schemas` 的代码注释过时。** [`oidc-module.ts` L76-L82](https://github.com/logto-io/logto/blob/v1.42.0/packages/schemas/src/foundations/jsonb-types/oidc-module.ts#L76-L82) 称 rotation「当 70% TTL 已过时签发新 token」（漏掉 public client 每次轮换）且「It can be turned off for only traditional web apps」。实际源码对任何应用类型都尊重 `rotateRefreshToken: false`（§1），Console 也对 Native/SPA 渲染该开关（只是换了一句「for each token request」的文案并提示 public client 建议保持开启，[RefreshTokenSettings.tsx L63-L72](https://github.com/logto-io/logto/blob/v1.42.0/packages/console/src/pages/ApplicationDetails/ApplicationDetailsContent/RefreshTokenSettings.tsx#L51-L73)、[phrases L70-L75](https://github.com/logto-io/logto/blob/v1.42.0/packages/phrases/src/locales/en/translation/admin-console/application-details.ts#L70-L75)）。当前网页文档「For public clients, it is highly recommended to keep refresh token rotation enabled」也印证开关对 public client 有效。
4. 小问题：Console 开关的「Learn more」链到旧文档路径 `docs.logto.io/docs/references/applications/#rotate-refresh-token`（[RefreshTokenSettings.tsx L58](https://github.com/logto-io/logto/blob/v1.42.0/packages/console/src/pages/ApplicationDetails/ApplicationDetailsContent/RefreshTokenSettings.tsx#L58)），依赖重定向。

## 5. 对 convex-logto 的含义

### 5.1 bridge 模式（localStorage）风险表述（ticket 01 动机 1）

默认配置下，Logto 对 SPA public client 已经实现了 RFC 9700 §4.14.2 要求的 rotation + reuse detection + 绝对过期三件套：每次 refresh 轮换、复用即整族吊销、整条链绝对 TTL 默认 14 天（可配至最长 180 天，另受 grant 180 天与 session 绑定约束）。因此文档中「refresh token 一旦从 localStorage 泄露即可长期静默滥用」的说法应当降级为：

- 攻击者拿到 token 后可以先用并持续轮换，但**受害者客户端下一次 refresh 会撞上已 consume 的 token，触发整族吊销**（双方都被登出，泄露从而可被察觉）；反过来受害者先刷新则攻击者手中 token 立即失效。
- 攻击者能维持的最长窗口是「受害者停止刷新」+ SPA 绝对 TTL（默认 14 天）；没有无限续命路径。
- 前提是保持默认配置：per-app 开关可以把 rotation 关掉（包括 SPA），文档表述应写明前提是保持默认 rotation 设置。
- 整族吊销不能召回已签发的 ID token/JWT（各自 `exp` 内仍可用），也不销毁 Logto session。

### 5.2 session component 的服务端 refresh 语义（ticket 08 动机 2）

- **Logto 对 confidential client 也会轮换**——不是每次，而是 ≥70% TTL 时。契约不能假设 refresh token 恒定：每次 token 响应都可能带新 `refresh_token`，**必须先原子持久化新 token 再认为 refresh 完成**；持久化失败后用旧 token 重试 = 复用 consumed token = 整族吊销、用户被迫重登。
- **必须单飞**：同一 grant 的 refresh 要串行化（跨实例需要锁或 compare-and-swap），因为服务端没有任何 reuse 宽限窗口。相对宽慰的是：默认 14 天 TTL 下轮换大约每 ~9.8 天才发生一次，未轮换期间旧 token 可重复使用，竞态暴露面比「每次轮换」的 SPA 小得多。
- 组件若自己再做一层「组件级 session token」轮换，两层轮换叠加的竞态只发生在 Logto 侧轮换的那次 refresh 上；契约里应把「Logto 返回了新 refresh_token 的那次刷新」当作需要强一致持久化的特殊路径。
- 链的硬上限：grant 180 天（硬编码，不可配）。服务端 session 想活过 180 天必须让用户重新走一次授权流程。
