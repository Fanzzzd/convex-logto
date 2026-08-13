# Convex component 能力边界：session component 需要的每项能力逐条验证

> 调研日期：2026-08-13
> 范围：Convex component 系统对 `convex-logto` 计划中的 auth "session component" 是否够用——自有 session 表、action 内 fetch Logto token endpoint、读取 client secret、注册 HTTP 路由（webhook）、cron（session GC）、以及浏览器 client 在**未认证**状态下调用 exchange/refresh。
> 来源约束：只使用 Convex 官方文档（docs.convex.dev，源码 pin 到 `get-convex/convex-backend` 具体 commit）、官方 `convex` npm 包（本仓库安装的 `convex@1.41.0`）、以及官方 component 仓库源码（pin 到具体 commit）。

## 结论先行

1. **session component 需要的每一项能力都有官方支持或官方组件先例，方案整体可行**；唯一"硬"限制是浏览器 client **不能**直接调用 component 函数，未认证的 exchange/refresh 必须走"app 层 wrapper 函数"或"component HTTP 路由"两条路之一。
2. **component 自有表是核心卖点**：component 在自己的 `schema.ts` 里定义表和索引，app 无法直接读写；每次 component mutation 是隔离的子事务，与 app 写入同事务提交。
3. **表的版本升级没有专门的官方迁移机制**：component 的 `schema.ts` 随 npm 包一起被 app 的 `npx convex dev/deploy` push，走和 app 完全相同的 schema push 校验——已有数据不匹配新 schema 时 push 直接失败。因此 component 作者要么只做向后兼容演进（`v.optional`），要么随包携带自己的 migration `internalMutation`（官方 `expo-push-notifications` 组件就是这么做的）。
4. **HTTP 路由有两种模式，官方 auth 组件全部选了第二种**：(a) component 自带 `http.ts`，app 用 `app.use(comp, { httpPrefix: "/x/" })` 挂载（convex ≥1.35）；(b) 在 component 的 **client 代码**里用 `httpActionGeneric` 定义 handler，由 app 在自己的 `convex/http.ts` 里调用 `registerRoutes(http)` 挂载。选 (b) 的原因是官方明确限制：**component 内的 HTTP action 拿不到 `ctx.auth`，也拿不到 app 的环境变量**。`@convex-dev/better-auth` 和 `@convex-dev/workos-authkit` 的全部 HTTP 路由（含 webhook）都是模式 (b)。
5. **cron 和 scheduler 在 component 内可用**：`ctx.scheduler` 是文档明确承诺的能力；`crons.ts` 官方文档未明说，但至少 3 个官方组件（action-retrier、action-cache、persistent-text-streaming）在 `src/component/crons.ts` 里用标准 `cronJobs()` 定义了 cron，是可依赖的先例。
6. **component action 可以 fetch 外网，但只有 V8 runtime**：CLI 在 bundle 阶段硬性报错 `"use node" directive is not supported in components`。Logto token endpoint 调用没问题（纯 fetch），但不能引入 Node-only 依赖——这与本仓库现有的 V8 约束一致。
7. **component 读不到 app 的 `process.env`（client secret 不会"自动"可见）**，有三条正规通路：① 系统变量 `CONVEX_CLOUD_URL` / `CONVEX_SITE_URL` 永远可见；② convex ≥1.39 的 typed env 声明（`defineComponent(name, { env: {...} })`，app 在 `app.use` 时传值或按引用绑定）；③ 由 app 层 client 类读 `process.env` 后当**函数参数**传进 component（workos-authkit 把 WorkOS `apiKey` 就这么传，甚至存进 component 自己的表）。
8. **`components.xxx` 引用只存在于 app 的服务端代码**（`convex/_generated/api` 的 `components` 对象，配 `ctx.runQuery/runMutation/runAction` 用）；浏览器端没有对应物。component 的"public"函数在 app 侧被降级为 internal 可见性，官方原话：*"can be called with `ctx.runQuery` … but **not** directly accessible from clients via HTTP or WebSockets"*。app 的 wrapper 函数默认是 public、任何 client（包括未认证）都能调，所以未认证 exchange/refresh 在 wrapper 层完全成立。
9. **注意**：`convex/server` 的类型注释仍标注 components 为 beta（"This is a feature of components, which are in beta. This API is unstable and may change"）；typed env（1.39.0）和 component `http.ts`（1.35.0）都较新，component 的 `peerDependencies.convex` 下限要按用到的特性来定。

## 版本与源码快照

| 来源 | 快照 | 备注 |
|---|---|---|
| Convex components 文档 | [docs.convex.dev/components](https://docs.convex.dev/components)（understanding / using / authoring）；文档源码 [`get-convex/convex-backend@4f855d1`](https://github.com/get-convex/convex-backend/tree/4f855d1dbb8f0d9d4f266d9040cf6e6ab8092f5c/npm-packages/docs/docs/components) | 引文以该 commit 的 `.mdx` 原文为准 |
| `convex` npm | `1.41.0`（本仓库 lockfile 安装版本），`dist/esm-types/server/components/index.d.ts` | 已含 `defineComponent` env 选项、`UseOptions.httpPrefix`、`createFunctionHandle` |
| `"use node"` 禁令 | [`npm-packages/convex/src/cli/lib/components/definition/bundle.ts`](https://github.com/get-convex/convex-backend/blob/4f855d1dbb8f0d9d4f266d9040cf6e6ab8092f5c/npm-packages/convex/src/cli/lib/components/definition/bundle.ts)（约 L752-757） | 报错原文 + `TODO(ENG-7116)` |
| `@convex-dev/better-auth` | `0.12.5`；[`2f9fcf6`](https://github.com/get-convex/better-auth/tree/2f9fcf6c3966bb27d38b2b83e80a1e914ab2a3ee)（main HEAD, 2026-08-11） | |
| `@convex-dev/workos-authkit` | `0.2.7`；[`b026110`](https://github.com/get-convex/workos-authkit/tree/b026110f3de67e69398143a48f6971ff1be50b20)（main HEAD, 2026-07-30） | |
| `@convex-dev/action-retrier` | [`769bfb3`](https://github.com/get-convex/action-retrier/blob/769bfb30a6f244928e1a846c7297afcfb9da8a78/src/component/crons.ts)（main HEAD） | component 内 `crons.ts` 先例 |
| `@convex-dev/expo-push-notifications` | [`082a1f9`](https://github.com/get-convex/expo-push-notifications/blob/082a1f98f29b53fcf9ce86a36d85165f2198db8b/src/component/migrations.ts)（main HEAD） | component 自带 migration 先例 |
| Schema push 校验 | [docs.convex.dev/database/schemas](https://docs.convex.dev/database/schemas) | "If there are documents that fail validation, the push will fail." |
| public vs internal functions | [docs.convex.dev/functions/internal-functions](https://docs.convex.dev/functions/internal-functions) | "By default your Convex functions are public and accessible to clients." |
| 官方 component 模板 | [get-convex/templates/template-component](https://github.com/get-convex/templates/tree/main/template-component) | `src/component` + `src/client` + `src/react` 布局 |

注：三个组件仓库 pin 的是 main HEAD 而非 release tag（better-auth 的 `package.json` 在该 commit 为 0.12.5，workos-authkit 为 0.2.7）。

## 能力总表

| session component 需要的能力 | 支持? | 证据 |
|---|---|---|
| 自有 session 表 + 索引 | ✅ | authoring.mdx："`schema.ts` — Defines a schema only accessible by the component"；workos-authkit `src/component/schema.ts` 三张表带 `.index()` |
| 表随 npm 版本升级演进 | ⚠️ 支持但自管 | 无专门迁移机制；走标准 schema push 校验（database/schemas），组件用 `v.optional` 兼容演进（workos-authkit schema）或自带 migration `internalMutation`（expo-push-notifications `src/component/migrations.ts`） |
| 注册 HTTP 路由（webhook） | ✅ 两种模式 | component `http.ts` + `httpPrefix`（convex CHANGELOG 1.35.0；using.mdx）；或 client 代码 `httpActionGeneric` + app `http.ts` 挂载（better-auth `create-client.ts` L373 `registerRoutes`；workos-authkit `client/index.ts` L237 `registerRoutes`） |
| cron（session GC） | ✅（文档未明说） | action-retrier / action-cache / persistent-text-streaming 均有 `src/component/crons.ts`，标准 `cronJobs()` |
| scheduler | ✅ | understanding.mdx："Components can schedule functions to run in the future and pass along state." |
| action 内 fetch 外网（Logto token endpoint） | ✅（仅 V8） | authoring.mdx env 示例即 `fetch(...)`；workos-authkit `lib.ts` 的 `internalAction` 里跑 `@workos-inc/node` SDK；`"use node"` 被 CLI 硬性拒绝 |
| 读 app 部署的 `process.env`（client secret） | ❌ 直读；✅ 三条替代 | authoring.mdx："cannot access just any value from the app's `process.env`"；替代：系统变量 / typed env 声明（convex ≥1.39）/ app 层传参（workos-authkit 把 `apiKey` 作为 `onWebhookEvent` 参数传入） |
| 浏览器 client 直调 component 函数 | ❌ | authoring.mdx："turned into references with 'internal' visibility … **not** directly accessible from clients via HTTP or WebSockets" |
| 未认证 client 调 exchange/refresh | ✅ 经 wrapper | app 侧 re-export 的 public 函数默认对任何 client 开放（internal-functions 文档）；better-auth `clientApi()` 即此模式；或 component HTTP 路由（`.convex.site` 上本就无 Convex 层认证） |
| component 内嵌套用其他 component | ✅ | workos-authkit `convex.config.ts`：`component.use(workpool)`、`component.use(workflow)` |

## 1. 自有表、索引与版本升级

component 目录里有自己的 `schema.ts`，官方描述为 *"Defines a schema only accessible by the component"*（authoring.mdx L34）。隔离性的官方原话（understanding.mdx L56-60）：

> "code inside a component can't read data that is not explicitly provided to it. This includes database tables, file storage, environment variables, scheduled functions, etc. Conversely, the component's data cannot be directly mutated by the main app."

事务性（understanding.mdx L64-71）：component mutation 与 app 的顶层 mutation 同事务提交（"You'll never have a component commit data but have the calling code roll back"），且每次 component mutation 调用是隔离子事务，caller 可以 catch component 抛出的异常后继续。这对 session 表非常合适——例如"写 session + 写 app 用户表"天然原子。

实例：workos-authkit 的 [`src/component/schema.ts`](https://github.com/get-convex/workos-authkit/blob/b026110f3de67e69398143a48f6971ff1be50b20/src/component/schema.ts) 定义 `events`（`.index("eventId", ...)`）、`backfillState`、`users`（`.index("id")` + `.index("externalId")`）三张表，语法与 app schema 完全一致。

**升级/迁移**：components 文档四页均无 "component 版本升级时表如何迁移" 的章节（诚实标注：这是文档空白，以下为推导 + 先例）。机制上，component 的 `schema.ts` 打进 npm 包（`dist/component/schema.js`），app 升级包版本后下一次 `npx convex dev/deploy` 会连同新 schema 一起 push，适用与 app 相同的校验规则（[database/schemas](https://docs.convex.dev/database/schemas)）：

> "The first push after a schema is added or modified will validate that all existing documents match the schema. If there are documents that fail validation, the push will fail."

所以 component 作者的两条现实路径：

- **向后兼容演进**：新字段一律 `v.optional(...)`。workos-authkit 的 `users` 表大量字段是 `v.optional(v.union(v.null(), v.string()))`，就是为了让旧行始终合法。
- **随包携带迁移函数**：官方 expo-push-notifications 组件在 [`src/component/migrations.ts`](https://github.com/get-convex/expo-push-notifications/blob/082a1f98f29b53fcf9ce86a36d85165f2198db8b/src/component/migrations.ts) 里提供 `internalMutation`（`resetLegacyInProgressNotifications`），对自己表里的 legacy 行做 patch，由使用方在升级后手动触发（dashboard / CLI 可指定 component 运行函数，convex CHANGELOG 有 `--component` 相关 flag）。

对 session 表的含义：session 数据天然短命，最坏情况"清空重登"可接受，所以 schema 演进压力远小于用户表；但仍应从第一版就把非必需字段设为 optional。

## 2. HTTP 路由：两种模式与官方 auth 组件的选择

### 模式 A：component 自带 `http.ts`（convex ≥1.35）

authoring.mdx L318 起：

> "Components can define their own `http.ts` file with HTTP routes, just like the main app. The app that installs the component chooses where these routes are accessible by specifying an `httpPrefix`."

app 侧（using.mdx）：`app.use(myComponent, { httpPrefix: "/my-component/" })`，路由出现在 `.convex.site` 域名的该前缀下；**"If no `httpPrefix` is provided, the component's HTTP routes are not exposed."** component 函数内的 `process.env.CONVEX_SITE_URL` 会反映含前缀的完整挂载 URL（自引用回调地址可用）。convex npm CHANGELOG 把该特性记在 **1.35.0**；`UseOptions.httpPrefix` 类型在本仓库安装的 1.41.0 中已存在（`dist/esm-types/server/components/index.d.ts` L81-88）。

但有官方明示的限制（authoring.mdx，加粗为原文）：

> "**Limitation:** Component HTTP actions do not have access to `ctx.auth` or the app's environment variables. If an HTTP handler needs to authenticate users or access data from the application, define the HTTP action handler in the component's client code and mount it in the app's `convex/http.ts` instead."

### 模式 B：client 代码定义 handler，app 的 `http.ts` 挂载

两个官方 auth 组件全部用模式 B：

- **better-auth**（[`src/client/create-client.ts`](https://github.com/get-convex/better-auth/blob/2f9fcf6c3966bb27d38b2b83e80a1e914ab2a3ee/src/client/create-client.ts) L373-493 `registerRoutes`，另有 L495 `registerRoutesLazy`）：用 `httpActionGeneric` 包一个把请求交给 Better Auth `auth.handler(request)` 的 handler，`http.route({ pathPrefix: "/api/auth/", method: "GET"|"POST", handler })` 注册到 **app 的** `HttpRouter`，可选用 `convex-helpers/server/cors` 的 `corsRouter` 做跨域；还注册 `/.well-known/openid-configuration` 重定向。整个 Better Auth 逻辑跑在 app 环境（有 app env vars、`ctx.auth`），component（`defineComponent("betterAuth")`，[convex.config.ts](https://github.com/get-convex/better-auth/blob/2f9fcf6c3966bb27d38b2b83e80a1e914ab2a3ee/src/component/convex.config.ts) 仅 5 行）只是纯数据 adapter：[`src/component/adapter.ts`](https://github.com/get-convex/better-auth/blob/2f9fcf6c3966bb27d38b2b83e80a1e914ab2a3ee/src/component/adapter.ts) 导出 `create/findOne/findMany/updateOne/...`，client 侧全部通过 `ctx.runQuery(component.adapter.findOne, ...)` 访问。
- **workos-authkit**（[`src/client/index.ts`](https://github.com/get-convex/workos-authkit/blob/b026110f3de67e69398143a48f6971ff1be50b20/src/client/index.ts) L237-313）：`AuthKit` 类的 `registerRoutes(http: HttpRouter)` 在 app 的 `http.ts` 注册 `/workos/webhook` 与 `/workos/action` 两个 `httpActionGeneric` 路由；webhook handler 在 **app 环境**里用 `this.workos.webhooks.constructEvent` 验签（secret 来自 app 的 `process.env.WORKOS_WEBHOOK_SECRET`），验完再 `ctx.runMutation(this.component.lib.onWebhookEvent, { apiKey, event, onEventHandle, ... })` 把事件连同 `apiKey` 一起传进 component。

**对 convex-logto 的含义**：Logto webhook 端点应沿用模式 B（现有 `registerLogtoWebhook()` 的形态天然吻合）——验签需要的 secret 在 app 环境读取。未来 custom-domain 下的 `/auth/*` 端点若不需要 `ctx.auth` / app env（比如 exchange 只要 component 自己的 typed env），模式 A 也可用。

## 3. cron 与 scheduler

- **scheduler**：官方承诺（understanding.mdx L43-44）："Durable functions via the built-in function scheduler. Components can schedule functions to run in the future and pass along state."。workpool/workflow 等官方组件的实现都建立在 component 内 `ctx.scheduler` 之上；function handle 可以传给 `ctx.scheduler.runAfter(0, handle, args)`（authoring.mdx Function Handles 一节）。
- **crons**：components 文档四页均未提及 `crons.ts`（诚实标注：无文档承诺）。但官方组件里有直接先例——[`action-retrier/src/component/crons.ts`](https://github.com/get-convex/action-retrier/blob/769bfb30a6f244928e1a846c7297afcfb9da8a78/src/component/crons.ts)：

  ```ts
  const crons = cronJobs();
  crons.interval("Cleanup expired runs", { hours: 24 }, internal.run.cleanupExpiredRuns);
  export default crons;
  ```

  action-cache、persistent-text-streaming 同样在 `src/component/crons.ts` 定义清理 cron（GitHub code search，org:get-convex）。这正是 session GC 想要的形态：component 自带每日/每小时清过期 session 的 cron，app 零配置。

## 4. fetch 外网与环境变量

### fetch：可以，但只有 V8 runtime

- authoring.mdx 的 typed env 示例本身就是 component action 里 `await fetch("https://api.example.com/translate", ...)`。
- workos-authkit 的 [`lib.ts`](https://github.com/get-convex/workos-authkit/blob/b026110f3de67e69398143a48f6971ff1be50b20/src/component/lib.ts) `updateEvents`（`internalAction`，无 `"use node"`）直接在 component 内跑 `new WorkOS(apiKey)` 并分页拉取 WorkOS Events API——证明 V8 action 从 component 内 fetch 第三方 API 是生产实践。
- **硬限制**：CLI bundler（[`bundle.ts`](https://github.com/get-convex/convex-backend/blob/4f855d1dbb8f0d9d4f266d9040cf6e6ab8092f5c/npm-packages/convex/src/cli/lib/components/definition/bundle.ts) 约 L752-757）直接 crash：

  > `"use node" directive is not supported in components. Remove it from the component at: ${resolvedPath}.`

  （注释 `TODO(ENG-7116) Remove error and bundle the component node actions when we are ready to support them.`——未来可能放开，现在不能依赖。）调 Logto token endpoint 是纯 `fetch` + `crypto.subtle`，与本仓库既有 V8 约束一致，无碍。

### 环境变量：component 读不到 app 的 env，三条正规通路

官方原话（authoring.mdx L220-224）：

> "A component's functions are isolated from the app's environment variables and cannot access just any value from the app's `process.env`. Only the system environment variables (`CONVEX_CLOUD_URL` and `CONVEX_SITE_URL`) are available in every component function."

三条通路：

1. **系统变量**：`CONVEX_CLOUD_URL` / `CONVEX_SITE_URL` 永远可见（且 `CONVEX_SITE_URL` 含 httpPrefix）。
2. **typed env 声明（convex ≥1.39.0）**：`defineComponent("logtoSession", { env: { LOGTO_CLIENT_SECRET: v.string(), ... } })`；app 必须在 `app.use(comp, { env: { ... } })` 提供值，或用 `app.env.X` 按引用绑定到 app 自己声明的 env var（"so the component always sees the current value"）。component 内经 `_generated/server` 的 `env` 导出以带类型方式读取（也镜像到 `process.env`，无类型）。注意官方提醒：**只能在 handler 内读，不能在模块顶层读**（部署分析阶段值不存在）。类型 API（`EnvDefinition`、`UseOptions.env`）在本仓库安装的 `convex@1.41.0` 中已存在；CHANGELOG 记录该特性首发于 **1.39.0**——若 session component 依赖它，`peerDependencies.convex` 至少要 `^1.39.0`。
3. **app 层传参**：authoring.mdx 明示替代："apps can still pass values as function arguments"。workos-authkit 的做法是 client 类（`AuthKit` 构造函数）在 app 环境读 `process.env.WORKOS_API_KEY` 等，然后把 `apiKey` 作为 `onWebhookEvent` mutation 的参数传进 component；backfill 流程甚至把 `apiKey` 写进 component 自己的 `backfillState` 表以便后续 action 使用。

⚠️ 未单独验证：component 自声明的 typed env 在 component 的 **HTTP action** 内是否可读。文档说 typed env "available … in all Convex functions within this component"，而 HTTP Actions 一节的 limitation 只说拿不到 **app 的** env vars——按行文推断 component 自己的 typed env 应可读，但没有找到显式例句或实测，落地前应实测一次。

## 5. 浏览器 client 与 component 函数：必须经 wrapper

官方原话（authoring.mdx L159-164）：

> "**Only public functions are accessible**: Internal functions are not exposed … The component's 'public' queries, mutations, and actions are turned into references with 'internal' visibility. They can be called with `ctx.runQuery`, `ctx.runMutation`, etc. but **not** directly accessible from clients via HTTP or WebSockets."

- `components.xxx` 是 app **服务端**代码里从 `./_generated/api` 导入的对象（using.mdx 例：`ctx.runQuery(components.agent.threads.getThread, ...)`）；`ConvexReactClient` 侧不存在 `components.*` 引用，浏览器只能调 app 自己 `api.*` 里的 public 函数。
- 因此"未认证的 exchange/refresh"的正确形态是 **re-export 模式**（authoring.mdx "Re-exporting component functions"，官方称之为 "the recommended pattern"）：component 的 client 包提供做好的函数，app 一行 re-export 成自己的 public 函数——better-auth 的 [`clientApi()`](https://github.com/get-convex/better-auth/blob/2f9fcf6c3966bb27d38b2b83e80a1e914ab2a3ee/src/client/create-client.ts)（`export const { getAuthUser } = authComponent.clientApi()`）就是现成先例。Convex public 函数默认对任何 client 开放（internal-functions 文档："By default your Convex functions are public and accessible to clients"），未认证调用没有障碍；参数校验就是普通的 `args` validator，且跨 component 边界的参数/返回值在运行时强制校验（understanding.mdx："Runtime validation ensures all data that cross a component boundary are validated"）。
- 备选：把 exchange/refresh 做成 HTTP 端点（模式 A 的 component `http.ts`，或模式 B 挂在 app `http.ts`）——better-auth 的浏览器流量（sign-in/sign-up/session）走的就是 `.convex.site` 上的 HTTP 路由 + CORS，而非 WebSocket 函数调用。
- 回调方向（component → app）用 **function handles**：`createFunctionHandle(ref)` 得到可存表、可跨边界传递的字符串，之后 cast 回 `FunctionHandle<"mutation">` 用 `ctx.runMutation` / `ctx.scheduler.runAfter` 调用，参数/返回值校验仍生效。workos-authkit 的 `onEventHandle`（app 的 `authKitEvent` 回调）即此用法——convex-logto 的"用户同步进 app 表"钩子可照搬。

## 6. 两个参照 component 的 package 布局（pinned）

两者都遵循官方 [template-component](https://github.com/get-convex/templates/tree/main/template-component) 的 `src/component`（Convex 函数 + schema，含 `_generated`）/ `src/client`（app 侧类与 helper）/ `src/react`（前端）三分结构。

### `@convex-dev/workos-authkit` 0.2.7（[`b026110`](https://github.com/get-convex/workos-authkit/tree/b026110f3de67e69398143a48f6971ff1be50b20)）

- `src/component/convex.config.ts`：`defineComponent("workOSAuthKit")`，并嵌套 `component.use(workpool, { name: "eventWorkpool" })` 与 `component.use(workflow, { name: "backfillWorkflow" })`——**component 组合 component** 的先例。
- `src/component/schema.ts`：`events` / `backfillState` / `users` 三张表。`src/component/lib.ts`：public `mutation onWebhookEvent`、public `query getAuthUser(ByExternalId)`、internal 的事件处理与 WorkOS API 拉取 action。
- `src/client/index.ts`：`AuthKit` 类，构造时收 `components.workOSAuthKit`（`ComponentApi` 类型）+ options，env 兜底读 app 的 `process.env.WORKOS_*`；`registerRoutes(http)` 注册 webhook/action 路由；`getAuthConfigProviders()` 供 `auth.config.ts`。
- `package.json` exports：`.`（client）、`./react`、`./convex.config`（+`.js` 双写）、`./_generated/component.js`（仅 types，给 `ComponentApi`）、`./test`。peer：`convex ^1.29.3`。

### `@convex-dev/better-auth` 0.12.5（[`2f9fcf6`](https://github.com/get-convex/better-auth/tree/2f9fcf6c3966bb27d38b2b83e80a1e914ab2a3ee)）

- `src/component/convex.config.ts`：`defineComponent("betterAuth")`（无嵌套、无 env 声明）。`src/component/schema.ts`（139 行，Better Auth 全部 auth 表）+ `adapter.ts`（由 `createApi(schema, ...)` 生成 CRUD 函数面）。
- `src/client/create-client.ts`：`createClient(components.betterAuth, config)` 返回带 `registerRoutes` / `registerRoutesLazy` / `clientApi()` / `triggersApi()` / `getAuthUser` 等的大对象；auth 业务逻辑（Better Auth 实例）完全在 app 环境执行，component 纯做存储。
- 入口远多于 workos：`.`、`./react`、`./nextjs(/client)`、`./react-start`、`./plugins`、`./client/plugins`、`./adapter`、`./auth-config`、`./convex.config(.js)`、`./_generated/component.js`、`./test`、`./utils`。peer：`convex ^1.25.0`。
- authoring.mdx 还点名 better-auth 是 "hybrid components"（支持 local-install，把 component 源码拷进 app 以便扩展 schema）的例子——如果 convex-logto 未来要允许 app 扩展 session 表字段，可参考。

## 对 convex-logto session component 的落地含义

1. session 表、token 交换 action、webhook、GC cron、用户同步回调——全部在能力边界内；架构上照抄 workos-authkit 的骨架（component 存储 + client 类 + `registerRoutes`）最省事。
2. client secret 的推荐通路：默认走 **app 层 client 类读 `process.env.LOGTO_CLIENT_SECRET` 后传参**（兼容 convex ≥1.25 级别的旧版本），typed env 声明作为可选增强（要求 convex ≥1.39，且顺带解决 component 内 http/cron 场景拿 secret 的问题——cron 触发的 GC 不经过 app 代码，传参通路对它不可用，typed env 或"存进自己表"才行，workos-authkit 选了后者）。
3. 未认证 exchange/refresh：提供 `clientApi()` 式的 ready-made public 函数让 app 一行 re-export；文档必须写明这是故意 public 的端点及其防滥用边界（参数校验 + Logto 侧的授权码/refresh token 本身即凭证）。
4. `pnpm` monorepo 注意 template 的告诫："Have a single package.json file and node_modules directory in the root of the project"（避免解析到双份 convex）；构建顺序 component codegen → build → example codegen。

## 未验证 / 不确定项

- component 版本升级迁移**没有官方文档章节**；上文结论是"schema push 校验规则 + 官方组件实践"的推导，Convex 未来可能提供一等迁移机制。
- component 内 `crons.ts` 无文档承诺，仅有官方组件先例（3 个）；上线前应在真实部署验证 cron 在 component 内确实注册并运行。
- component 自声明 typed env 在 component HTTP action 内是否可读：按文档行文推断可以，未实测。
- components 整体仍被 `convex/server` 类型注释标注为 beta；`"use node"` 禁令带 `TODO(ENG-7116)`，说明限制可能变化。
- 三个参照仓库 pin 的是 main HEAD 而非 npm release tag；npm 上对应版本的构建产物未逐一 diff。
