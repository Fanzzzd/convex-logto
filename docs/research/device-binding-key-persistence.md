# 设备绑定：不可导出密钥在浏览器中的持久性研究

> 调研日期：2026-08-13
> 范围：Web SPA 用 WebCrypto 生成 `extractable: false` 的 ECDSA P-256 密钥对、以 structured clone 存入 IndexedDB、每次 session refresh 对 challenge 签名的可行性。对应 issue 04，为 issue 11（设备绑定去留决策）提供数据。React Native 不在本文范围内。
> 资料原则：只引用规范（W3C/IETF）、浏览器厂商官方博客与文档（webkit.org、developer.chrome.com、MDN、Firefox release notes）和官方 bug tracker。二手数据（如未经官方公告核实的 Chrome 版本号）会显式标注。

## 结论先行

1. **建议 opt-in，不默认开，也不放弃。** 决定性证据：(a) 技术上完全可行且是规范推荐做法（见 2）；(b) 在当前"token 存 localStorage"的默认架构下，绑定密钥引入的**增量**登录失败约等于零，因为所有已知的清除路径（Safari ITP 7 天、存储压力 eviction、隐私模式结束、用户清站点数据）都是整个 origin 的脚本可写存储**一起**清，密钥和 token 同生共死（见 4、8）；(c) 但安全增益有明确上界：软件密钥只绑定浏览器 profile 而非硬件，XSS 攻击者仍可在页面内代签或换自己的密钥重跑流程（见 6）；(d) 一旦未来引入 cookie transport（issue 13），Safari 上会出现**真正的**增量失败面，server-set cookie 可以在 ITP 清除中幸存而 IndexedDB 密钥不能，绑定会把本可幸存的会话拖死（见 4.3）。默认开的收益/风险比不成立，放弃则浪费一个对"token 纯外传"类攻击确实有效、且有 DPoP 先例的低成本防线。
2. **CryptoKey 存 IndexedDB 是 W3C 规范明文推荐的模式，非 hack。** Web Cryptography API 规定 CryptoKey 是 serializable object，序列化时 `[[extractable]]` 与 `[[usages]]` 内部槽被原样保存和恢复，**不可导出性跨 structured clone / IndexedDB 持久化后依然成立**。规范 §5.2 明确预期作者用 IndexedDB 存 key"而不向应用暴露 key material"。三大浏览器自 2015 年 7 月起对 CryptoKey 达到 MDN Baseline"Widely available"，常规模式下跨 reload 与浏览器重启均持久。
3. **Safari ITP 的 7 天上限确认覆盖 IndexedDB。** WebKit 2020-03-24 官方博客与现行 tracking-prevention 政策页都把 IndexedDB 列入"script-writable storage"清除清单：用户以 first party 身份对站点无交互达 7 个"Safari 使用日"后全部清除。豁免只有两个：加到主屏幕的 web app、以及 server 设置的 cookie。`navigator.storage.persist()` 未被列为豁免。截至调研日（2026-08）政策页仍列此条，**未发现放宽**。
4. **但 ITP 清除是"整批"的：密钥被清时 localStorage 里的 Logto token 也同批被清**，用户本来就要重登。所以在现行架构下，ITP 不构成反对设备绑定的理由，它构成的是反对"浏览器端任何长期凭据"的理由（这点在 [auth-storage-and-bootstrap.md](./auth-storage-and-bootstrap.md) 已有结论）。
5. **隐私模式三家均可用、均为会话级**：Chrome/Edge 数据在隐私会话结束时删除；Firefox 115（2023-07）起 IndexedDB 在隐私窗口完整可用（磁盘加密、密钥仅存内存、会话结束清除）；Safari 17+"Private Browsing 2.0"每个 tab 独立 ephemeral session。密钥生成与使用不受阻，生命周期与 token 相同，隐私模式下用户本来每次都要重登，无增量伤害。
6. **多 tab 并发签名本身无锁问题**（CryptoKey 不可变，`sign()` 无独占语义，此句为推断，规范无相反描述）；需要治理的是**enroll 竞态**（两个 tab 各自生成密钥去注册）与 refresh 单飞，用 Web Locks API（`navigator.locks`，Baseline 自 2022-03，对应 Safari 15.4 一代）+ IndexedDB 事务即可，属已知工程问题而非平台缺陷。
7. **先例充分，且未来已经有更好的路径。** panva/oauth4webapi 的 DPoP 文档原话：浏览器环境"shall use IndexedDB to persist the generated CryptoKeyPair"，与本方案完全同构。更重要的是 **DBSC（Device Bound Session Credentials）**：W3C WebAppSec WG Editor's Draft（2026-04-17 版），TPM 级密钥绑定 + 周期性 challenge 签名，2026-05-28 Google 官宣在 Windows 版 Chrome 正式 GA（对 Workspace 客户默认开启）。DBSC 做的正是本方案想做的事，但密钥在安全硬件里。软件密钥方案应定位为"DBSC 不可用平台上的过渡性 opt-in"，并在文档里写明。

## 1. 规范层：CryptoKey 的可序列化与不可导出性

Web Cryptography API 对三个关键问题都有明文：

- **可序列化**："CryptoKey objects are serializable objects"，序列化步骤把 `[[extractable]]`、`[[usages]]` 内部槽写入序列化记录并在反序列化时原样恢复（spec §13.5，节号以现行 Editor's Draft 为准）。即：`extractable: false` 的密钥存进 IndexedDB、重启浏览器读出来，**仍然**不可导出，`exportKey` 依旧抛错。
- **推荐存储**：spec §5.2："it is expected that most authors will make use of the Indexed Database API… without ever exposing that key material to the application"。
- **边界**：spec §6.2 提醒同 scheme+host+port 的所有代码共享同一存储分区（XSS 同源即可用到 key，见 6）；且"conforming user agents are not required to zeroize key material"，规范不保证密钥材料在磁盘上的物理防护。

来源：[W3C Web Cryptography API（Editor's Draft）](https://w3c.github.io/webcrypto/)。

## 2. 各浏览器常规模式：持久性与已知坑

- **兼容性基线**：MDN 标注 CryptoKey 为 Baseline"Widely available"，"available across browsers since July 2015"。来源：[MDN CryptoKey](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey)。ECDSA P-256 属最早落地的算法集，三家均支持。
- **Safari 的实现姿态**：WebKit 2017-07-21 博客明确其 WebCrypto"protects the secret or private keys by storing them completely outside of the JavaScript execution context"，并把不可导出性描述为"reduces the risk of the private key being exfiltrated and reduces the window of compromise if an attacker gets to execute JavaScript in the victim's browser"。来源：[Update on Web Cryptography（webkit.org）](https://webkit.org/blog/7790/update-on-web-cryptography/)。
- **Safari IndexedDB 的历史可靠性问题**（与 CryptoKey 无关，是 IndexedDB 本体）：
  - iOS 14.6 / Safari 14.1：首次启动后第一个 `indexedDB.open()` 可能永久 pending，14.7 修复；社区当年靠 [safari-14-idb-fix](https://github.com/jakearchibald/safari-14-idb-fix) 兜底。来源：[WebKit bug 226547](https://bugs.webkit.org/show_bug.cgi?id=226547)。
  - iOS 15.2.1：PWA 场景"An internal error was encountered in the Indexed Database server"。来源：[WebKit bug 235579](https://bugs.webkit.org/show_bug.cgi?id=235579)。
  - 结论：老版本 Safari 上 IndexedDB open 失败是真实存在过的小概率事件。任何绑定实现都必须把"打不开 IndexedDB"当作一等降级路径（回退为不绑定或重新 enroll），不能当作异常崩溃。
- **Chrome / Firefox**：未发现 CryptoKey-in-IndexedDB 跨重启丢失的官方 bug 记录（未做穷尽式 bug tracker 检索，此处为"未发现"而非"不存在"）。eviction 见 4.2。

## 3. 隐私模式

| 浏览器 | IndexedDB 可用？ | 生命周期 | 来源 |
| --- | --- | --- | --- |
| Chrome/Edge（Incognito/InPrivate） | 可用 | "stored data is usually deleted when the private browsing mode ends" | [MDN Storage quotas and eviction criteria](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria) |
| Firefox 115+（2023-07） | 完整可用，无内存限制 | 磁盘加密存储、解密密钥仅存 RAM，会话正常结束时全部清除 | [Firefox 115.0 release notes](https://www.firefox.com/en-US/firefox/115.0/releasenotes/)、[Bugzilla 1639542](https://bugzilla.mozilla.org/show_bug.cgi?id=1639542) |
| Safari 17+（Private Browsing 2.0） | 可用 | 每个 tab 一个独立 ephemeral session（内存态，退出即失）；第三方 LocalStorage/IndexedDB 按 first party 分区且 ephemeral | [Private Browsing 2.0（webkit.org）](https://webkit.org/blog/15697/private-browsing-2-0/) |

对绑定方案的含义：隐私模式下 enroll 正常工作，密钥与 token 同为会话级，用户在隐私模式下本来就没有跨会话登录态，绑定不新增任何失败。唯一注意点是 Safari 的 per-tab session：两个隐私 tab 是两套存储、两把密钥、两个会话，实现上不能假设"同 origin 必同密钥"。

## 4. Safari ITP 7 天上限：覆盖范围与真实伤害面

### 4.1 政策事实

- 2020-03-24 公告："deleting all of a website's script-writable storage after seven days of Safari use without user interaction on the site"，明列 **Indexed DB**、LocalStorage、Media keys、SessionStorage、Service Worker registrations and cache。计数单位是"Safari 使用日"而非日历日，一周只开两天 Safari 的用户，日历上可拖到三周以上。豁免：加到主屏幕的 web app"are not part of Safari and thus have their own counter of days of use"，官方原话"We do not expect the first-party in such a web application to have its website data deleted"。来源：[Full Third-Party Cookie Blocking and More（webkit.org）](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/)。
- 现行政策页（截至调研日）仍列此条："deletes all cookies created in JavaScript and all other script-writeable storage after 7 days of no user interaction with the website"，并确认主屏 web app 豁免。**未提及** `navigator.storage.persist()` 可豁免，应按"persist() 不保护"设计（不确定性标注：未找到 WebKit 对 persist() 与 ITP 关系的正面声明，此为保守假设）。来源：[Tracking Prevention in WebKit](https://webkit.org/tracking-prevention/)。
- MDN 独立佐证并补充关键豁免："If an origin has no user interaction, such as click or tap, in the last seven days of browser use, its data created from script will be deleted. **Cookies set by server are exempt from this eviction.**"来源：[MDN Storage quotas and eviction criteria](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria)。
- **2026 年是否放宽**：未发现任何放宽公告；tracking-prevention 政策页作为 canonical 文档仍保留该条。（检索面：webkit.org 博客与政策页；未逐篇核查 2024 到 2026 全部 WebKit 博客，置信度中高。）

### 4.2 清除/eviction 的"整批性"，本研究最重要的事实

MDN："When an origin's data is evicted by the browser, **all of its data, not parts of it, is deleted at the same time**"，IndexedDB 与其他存储同批消失；ITP 的 7 天清除同样是"all script-writable storage"一起。这意味着：

**绑定密钥（IndexedDB）和 Logto token（localStorage，见 [auth-storage-and-bootstrap.md](./auth-storage-and-bootstrap.md) 结论 1）在所有平台级清除路径上是同生共死的。** 密钥没了的那一刻 token 也没了，用户走的是本来就会走的重新登录，而不是"token 还在却因缺密钥被拒"的新型失败。

### 4.3 量化失败面

| 场景 | 绑定密钥 | 浏览器端凭据（localStorage token） | 增量登录失败？ |
| --- | --- | --- | --- |
| Safari 常规模式，7 个使用日内有交互 | 保留 | 保留 | 无 |
| Safari 常规模式，≥7 使用日无交互（ITP 清除） | 清除 | **同批清除** | 无（本来就要重登） |
| Safari 主屏 PWA | 豁免 | 豁免 | 无 |
| 隐私模式（三家） | 会话级 | 会话级 | 无 |
| 存储压力 eviction（三家，LRU 整 origin） | 清除 | 同批清除 | 无 |
| 用户手动清站点数据 | 清除 | 同批清除 | 无 |
| 老版本 Safari IndexedDB open 失败（bug 226547 类） | 不可用 | 可用 | **有**（小概率、已修复版本为主；需降级路径兜底） |
| **未来 cookie transport（issue 13）+ Safari ≥7 使用日无交互** | 清除 | **server-set cookie 幸存**（ITP 豁免） | **有，这是唯一系统性的增量失败** |

结论：在 token 存 localStorage 的现状下，"Safari 7 天清掉密钥导致强制重登"这个担忧**不成立**为反对理由，它清掉的不只是密钥。真正的红线出现在 cookie transport 模式：绑定会把 Safari 回访用户（>7 使用日）本可用 HttpOnly cookie 延续的会话拖死。因此绑定与 cookie transport 的组合在 Safari 上应默认互斥或给出明确警告。

## 5. 多 tab 并发

- **签名并发**：CryptoKey 对象只读、`crypto.subtle.sign()` 无独占/锁语义，多 tab 从 IndexedDB 各自读出同一密钥并发签名没有平台层冲突。（推断：WebCrypto 规范未定义任何互斥概念；未发现相关浏览器 bug。）
- **需要自己治理的两个竞态**：
  1. **enroll 竞态**：两个 tab 同时发现"无密钥"，各自 `generateKey` 并注册，服务端只认一把时另一 tab 的会话报废。解法：`navigator.locks.request("device-key", …)` 内做"读-无则生成-写"，IndexedDB `readwrite` 事务保证单写入。
  2. **refresh 单飞**：challenge 签名绑定到某次 refresh，多 tab 同时 refresh 本就需要单飞（issue 08 的契约问题），加签名不改变问题形状。
- Web Locks API：MDN Baseline"Widely available"自 2022-03（对应 Safari 15.4 一代），明确定位就是"a web app running in multiple tabs or workers to coordinate work"。来源：[MDN Web Locks API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API)。

## 6. 安全增益的诚实边界

方案宣称的收益是"session token 被偷后离开该浏览器即废纸"。这个具体目标**成立**。token 纯外传（infostealer 抓 localStorage/网络日志、日志泄露、肩窥复制）后，攻击者没有私钥、签不了 challenge。但边界必须写清：

1. **不是硬件绑定**。`extractable: false` 只是 JS API 层的承诺；密钥材料仍以浏览器 profile 文件形式存在磁盘上，规范既不要求 zeroize 也不要求对本地攻击者防护（spec §6.2）。能读磁盘的恶意软件可以连 profile 一起偷走。绑定的是"这个浏览器 profile"，不是"这台设备"。
2. **挡不住在场的 XSS**。IETF browser-based apps 文稿（以 DPoP 为镜像案例）：攻击者拿到 token 后"can only abuse stolen application tokens by carrying out an online attack, where the proofs are calculated in the user's browser"，即攻击者退化为必须在受害者页面里在线代签；但同一文稿同时指出攻击者可以自己发起新授权流程配上**自己的**密钥对，"Advanced security mechanism, such as DPoP… are equally ineffective"于攻击者自启的静默授权流。来源：[draft-ietf-oauth-browser-based-apps-27 §5.2.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-27)。
3. 因此定位应是：**把"离线可转卖的 token"降级为"必须保持在场的在线攻击"**，这是有意义但有限的一层，不能当作 XSS 答案来营销。

## 7. 先例与未来路径

### 7.1 DPoP 浏览器实现（同构先例）

panva/oauth4webapi（浏览器可用的 OAuth 库，Logto 生态外最主流的 Web API 系实现）DPoP 文档原话："In order to take full advantage of DPoP you shall generate a random private key for every session. **In the browser environment you shall use IndexedDB to persist the generated CryptoKeyPair.**"来源：[oauth4webapi DPoP example](https://github.com/panva/oauth4webapi/blob/main/examples/dpop.ts)。即"不可导出 CryptoKeyPair + IndexedDB 持久化 + 每请求签名"在生产库里已是既定模式。

### 7.2 DBSC：浏览器原生的设备绑定（2026 现状）

- 规范：[Device Bound Session Credentials（W3C Editor's Draft, 2026-04-17）](https://w3c.github.io/webappsec-dbsc/)，由 **W3C Web Application Security WG** 制定；核心是浏览器持有"securely-stored private key"（TPM/OS 级），周期性对 refresh challenge 签名以证明会话未离开设备，与本方案协议形状相同，密钥强度高一档。
- Chrome 进度：第一轮 origin trial 至 M139/M140（[公告](https://developer.chrome.com/blog/dbsc-origin-trial)）；第二轮 2025-10 起至 2026 年 2 月初，限 **Windows + TPM**，引入 `Secure-Session-` 头系与跨站会话共享（[公告](https://developer.chrome.com/blog/dbsc-origin-trial-update)）；**2026-05-28 Google 官宣 Windows 版 Chrome 正式 GA**，对 Workspace 客户默认开启、无管理员开关（[Workspace Updates](https://workspaceupdates.googleblog.com/2026/05/prevent-account-takeovers-with-DBSC-now-generally-available-in-the-Chrome-browser-for-Windows.html)；GA 公告未写 Chrome 版本号，二手来源称 146 / macOS Secure Enclave 支持在后续版本，未经官方核实）。
- Safari / Firefox：未发现实现或正式立场声明（未逐一核查 mozilla/webkit standards-positions 仓库，置信度中）。
- 含义：**Chrome/Windows 上浏览器已经原生做了本方案想做的事，且是硬件密钥。** 软件密钥的 IndexedDB 方案价值在于覆盖 DBSC 未到的平台（Safari、Firefox、macOS Chrome 过渡期），并且是应用层协议、Logto/Convex 侧可控。设计文档应明确：本方案是 DBSC 的软件降级位，接口上给未来接 DBSC 留缝。

## 8. 对 issue 11 的建议：opt-in

- **不默认开**：(a) 安全增益有 §6 的上界，卖点必须收敛为"反 token 外传"；(b) 老 Safari IndexedDB 打不开的兜底、多 tab enroll 锁、challenge 协议都是新增复杂度，默认开会把这些成本摊给所有用户；(c) 与未来 cookie transport 在 Safari 上冲突（4.3）；(d) DBSC 已在最大平台 GA，默认开一个注定被原生方案替代的软件版不划算。
- **不放弃**：(a) 在现状架构下增量登录失败≈0（4.3 表），"宁可 opt-in 也不为 5% 安全增益引 20% 登录失败"的红线根本没被触到；(b) 对 infostealer 式 token 外传是实打实的防线，且有 oauth4webapi/DPoP 先例背书；(c) 实现成本已被本研究收敛为三个已知工程点（IndexedDB 降级、Web Locks enroll、refresh 单飞）。
- **opt-in 的降级契约**：密钥缺失/IndexedDB 不可用 ⇒ 视为未 enroll，走正常登录后重新 enroll；绝不能变成死循环或硬错误。Safari + cookie transport 组合默认不绑定或文档级警告。

## 附：来源清单

| 主题 | 来源 | 日期 |
| --- | --- | --- |
| CryptoKey 序列化、IndexedDB 推荐、零化边界 | [W3C Web Cryptography API ED](https://w3c.github.io/webcrypto/) | 现行 ED（2026-08 访问） |
| CryptoKey Baseline | [MDN CryptoKey](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey) | 2015-07 起 Baseline |
| Safari WebCrypto 实现姿态 | [webkit.org/blog/7790](https://webkit.org/blog/7790/update-on-web-cryptography/) | 2017-07-21 |
| ITP 7 天上限（原始公告） | [webkit.org/blog/10218](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/) | 2020-03-24 |
| ITP 现行政策 | [webkit.org/tracking-prevention](https://webkit.org/tracking-prevention/) | 2026-08 访问 |
| eviction 整批性、server cookie 豁免、隐私模式 | [MDN Storage quotas & eviction](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria) | 2026-08 访问 |
| Firefox 隐私模式 IndexedDB | [Firefox 115 release notes](https://www.firefox.com/en-US/firefox/115.0/releasenotes/) / [Bug 1639542](https://bugzilla.mozilla.org/show_bug.cgi?id=1639542) | 2023-07-04 |
| Safari 隐私模式 | [webkit.org/blog/15697](https://webkit.org/blog/15697/private-browsing-2-0/) | 2024-07 |
| Safari IndexedDB 可靠性 | [WebKit bug 226547](https://bugs.webkit.org/show_bug.cgi?id=226547) / [235579](https://bugs.webkit.org/show_bug.cgi?id=235579) | 2021 到 2022 |
| 多 tab 协调 | [MDN Web Locks API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API) | Baseline 2022-03 |
| DPoP 在浏览器的边界 | [draft-ietf-oauth-browser-based-apps-27 §5.2.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps-27) | draft-27 |
| DPoP + IndexedDB 先例 | [oauth4webapi dpop.ts](https://github.com/panva/oauth4webapi/blob/main/examples/dpop.ts) | 2026-08 访问 |
| DBSC 规范 | [w3c.github.io/webappsec-dbsc](https://w3c.github.io/webappsec-dbsc/) | ED 2026-04-17 |
| DBSC origin trial / GA | [OT1](https://developer.chrome.com/blog/dbsc-origin-trial) / [OT2](https://developer.chrome.com/blog/dbsc-origin-trial-update) / [GA 公告](https://workspaceupdates.googleblog.com/2026/05/prevent-account-takeovers-with-DBSC-now-generally-available-in-the-Chrome-browser-for-Windows.html) | 2025-10 / 2026-05-28 |
