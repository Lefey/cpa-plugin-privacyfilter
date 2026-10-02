# CPA Plugin Privacy Filter

[English](README.md) | 简体中文

面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的协议感知型请求侧隐私过滤插件。它会在受支持的请求文本发送给上游模型前，对选定的 PII 和凭证做不可逆脱敏；默认主动终止无法安全检查的请求。在此基础上有两个需要显式开启的功能：[`key_filter`](#只对指定-api-key-启用过滤) 让过滤只作用于选定的客户端 API key；[`mode: tokenize`](#可逆-token-化mode-tokenize) 把命中值替换为 token，并在上游响应返回客户端之前把 token 还原为原始值。

> **不要安装官方 Plugin Store 中名为 `privacyfilter` 的条目。** 截至 2026-09-15，该 [Store 记录](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store/blob/main/registry.json) 属于 `rheodev`，并指向他们的旧版 v0.2.0 实现。此 `ahoo` 分支不会申请另一个冲突的 Store 标识。只应安装从本仓库不可变 Release 下载并校验过 checksum 的产物。
>
> 不要安装 `v0.3.0`：其产物集虽通过了 Release gate，但发布时仓库尚未启用 Release immutability。`v0.3.1` 的发布工作流 fail closed 后仍是未发布的 draft。`v0.3.2` 是首个不可变 Release。`v0.3.3` 因扩展后的 exact-Host assertion 尚未登记到 release-manifest validator，在创建 Release 前发布 gate 主动失败。`v0.3.4` 同时包含 Responses Lite/Codex 兼容修复和对应 validator 更新；`v0.3.5` 新增经校验的 OpenRouter `reasoning_details` replay 兼容和无值拒绝诊断。只有 GitHub 将对应 Release 标记为 immutable 后，才可安装其中通过 checksum 校验的产物。不要安装源码树或开发 build；执行下方示例前，应核对精确版本和文件名。

## 安全模型

- 理解 OpenAI Chat Completions、OpenAI Responses、Anthropic Messages、Gemini GenerateContent 和 Interactions 请求结构。
- 检查协议 walker 明确分类为模型可见的 system、user、assistant/replay、工具输入/输出、工具描述和工具 schema 文本。
- 脱敏常见 PII、Gitleaks 风格密钥，以及结构化工具数据中位于精确高置信凭证字段下的短值。
- 只改写选中的 JSON 字符串值，永不改写对象键。未修改的空白、成员顺序、重复键、转义和数字字面量保持原始字节不变。
- 使用请求内不可逆占位符。同一逻辑请求中的相同值复用一个占位符，同类型不同值会编号区分。第二次 interceptor 扫描只信任本请求实际生成过的占位符。
- 为已知协议对象中的每个字符串分配一种明确处置：可脱敏内容、明确定义的不透明控制/完整性数据，或不支持。含未知字符串的扩展会 fail closed，不会被静默跳过。
- 默认使用 `mode: redact`、`on_error: block`、内嵌规则、无模型/格式绕过、无 blocking rule ID。
- 使用 RPC schema 2 主动终止。被拒绝的请求以成功的插件 RPC envelope 返回，并设置 `Terminate: true`，避免宿主因普通 interceptor error 的 fail-open 行为而继续转发。
- 日志只包含计数、常量失败类别和经过 allowlist 限定的有界 schema 路径；未知对象键显示为 `<redacted>`。插件不会记录命中值、错误详情或请求体。

默认的 `mode: redact` 是**不可逆脱敏**：插件不保留原始值。只有显式开启的 `mode: tokenize` 会在内存中保留有界的映射，用于在响应中还原；见[可逆 token 化](#可逆-token-化mode-tokenize)。

## 支持的请求格式

`SourceFormat` 必须精确匹配：

| `SourceFormat` | 请求协议 | 检查内容 |
|---|---|---|
| `openai` | Chat Completions | 消息文本、多段文本、旧版/新版函数参数、tool role 输出、函数描述和参数 schema；经校验的 OpenRouter `reasoning`/`reasoning_content`/`reasoning_details` replay 保持不透明且字节不变 |
| `openai-response` | Responses | instructions、input/replay 文本、prompt variables、Responses Lite `additional_tools`、function/custom/namespace/tool-search/web-search 定义、当前工具历史、函数描述、输入/输出 schema、text-format schema，以及编码的 Codex turn metadata |
| `claude` | Anthropic Messages | 顶层 system、消息文本、`tool_use.input`、字符串/结构化 `tool_result.content`、工具描述和 input schema |
| `gemini` | Gemini GenerateContent | system/content 文本、函数参数/结果、可执行代码/结果、display name、函数描述和参数/响应 schema |
| `interactions` | Interactions | system instruction、嵌套 input/steps/content、函数输入/输出、工具描述和 schema |
| `gemini-cli` | Interactions 兼容别名 | 与 `interactions` 相同 |

已知控制和完整性字段保持不透明，包括 model/role/type discriminator、工具名称和 ID、call ID、status、签名、加密 reasoning、经校验的 provider reasoning replay（`reasoning`、`reasoning_content` 以及 `reasoning.text`/`reasoning.summary`/`reasoning.encrypted` detail union）、二进制/base64 数据、明确定义的 URL/文件引用，以及 Codex `client_metadata` 的已知扁平传输/会话值。编码的 `x-codex-turn-metadata` 对象和新增的未知 metadata 会递归检查，而不会仅因客户端增加 telemetry 字段就返回兼容性 422；已知扁平传输 ID 保持不透明。不支持的 Responses 根级工具类型仍会被拒绝，而不是作为不透明对象转发。

### 结构化凭证字段

在已识别的结构化工具输入/输出中，精确凭证字段下的非空、非模板字符串会被整值脱敏，即使值很短或熵很低。支持的精确字段族包括：

- `AK`、`SK`、`api_key`、`api_secret`、`api_secret_key`；
- `access_key`、`access_key_id`、`secret_key`、`secret_access_key`；
- AWS access/secret key 字段、`client_secret` 和 `private_key`；
- access/API/auth/refresh/session/ID/client/secret/bearer/OAuth token 字段；
- `password`、`passwd`、`pwd`、`credential`、`secret`、`secrets` 和 `authorization`。

字段键在 64 字节上限内进行 ASCII case-fold，并把 `-` 归一化为 `_`；匹配发生在归一化之后，`apikey`、`accesskeyid` 等连续形式作为精确条目覆盖相应 camelCase 字段。`AK` 和 `SK` 只在其自身是直接字段名时触发整值处理；它们不会像较长且歧义较小的凭证字段名那样向后代字符串传播。这样会保留普通的 DynamoDB `{"SK":{"S":"..."}}` 结构，同时仍脱敏 `{"SK":"..."}`。这是精确 allowlist，不是子串匹配：`monkey`、`token_id`、`api_key_name`、`secret_name`、`client_id` 和任意 `MY_SECRET_KEY` 风格名称不会仅凭字段名触发整值规则。通用 PII/密钥 detector 仍会检查这些字段值。模板变量和已识别的 mask 占位符保持不变。

## 检测能力与占位符

检测引擎组合了：

- 邮箱地址；
- 中国大陆手机号和身份证号；
- 通过 Luhn 校验的银行卡号；
- IPv4 地址；
- 带上下文和高熵特征的密钥检测；
- 精确结构化凭证字段检测；
- pinned Gitleaks 快照中适用于请求文本的 regex、keyword、entropy、capture group 和 allowlist 语义。

默认占位符：

| 类型 | 第一个不同值 | 第二个不同值 |
|---|---|---|
| `email` | `[邮箱]` | `[邮箱#2]` |
| `phone` | `[电话]` | `[电话#2]` |
| `id_card` | `[身份证]` | `[身份证#2]` |
| `bank_card` | `[银行卡]` | `[银行卡#2]` |
| `ip` | `[IP]` | `[IP#2]` |
| `secret` | `[密钥]` | `[密钥#2]` |

请求缓存只保留哈希和替换标签，不保留命中明文或可恢复映射。`mode: tokenize` 下另有一个 token vault 在内存中保存原始值，见下文。

## 固定资源边界

下列 hard maximum 不能通过配置提高或关闭：

| 资源 | Hard maximum |
|---|---:|
| Native RPC envelope | 64 MiB |
| 请求体 | 32 MiB |
| JSON 深度 | 128 |
| 外层与编码 JSON 累计 value 数 | 250,000 |
| scanner/walker 保守统计的结构保留量 | 128 MiB |
| 单个解码字符串或 replacement | 8 MiB |
| Replacement 数 | 100,000 |
| 编码后 replacement 输出 | 32 MiB |
| 累计 detector 文本 | 32 MiB |
| Detector 文本节点 | 100,000 |
| Finding 数 | 4,096 |
| 并发 native scan | 4 |
| Native admission 等待 | 100 ms |
| Native 检查 deadline | 10 秒 |

受支持工具输入/输出中的 JSON 容器，无论位于标量、typed/list 文本还是原生结构化数据的字符串字段中，都会被递归检查。编码 JSON 和递归编码 JSON 与外层请求共享 JSON node、结构、detector、finding 和 replacement 预算；另外最多递归四层编码容器。Native 工作保持同步，返回请求后不会遗留 scanner goroutine。C ABI 无法传递客户端 cancellation，因此使用内部 deadline，并在有界扫描操作之间检查取消；正在执行的单次 Go 正则表达式操作无法被强制中断。

配置可以降低、但不能提高这些 hard maximum。Payload scan/replacement 限制为零时使用对应的有界默认值；detector 限制必须为正数。

## 环境要求

- 支持 native plugin ABI 1 的官方 CLIProxyAPI build。完整 fail-closed 行为要求宿主 RPC schema 不低于 2；插件会协商 schema 2。在 schema-1 宿主上，配置 `on_error: block` 或任意 `block_rule_ids` 都会导致注册失败。
- `mode: tokenize` 会额外注册 response 和 stream-chunk interceptor，并协商宿主 RPC schema 5，使宿主不再随每个流式 chunk 重发请求体和 chunk 历史。在较旧的宿主上仍可工作（按协商到的 schema），但每个 chunk 都带有这部分开销。其他模式的注册内容不变。
- 插件使用 CLIProxyAPI SDK v7.2.157 编译。Release 必须在 manifest 中记录隔离集成 gate 使用的官方 Host image 和精确 digest，否则不得发布。
- 从源码构建需要 Go 1.26 和 CGO。
- 对应目标平台的原生 C 工具链。

## 安装

把同一个不可变 Release 的全部 asset 下载到新目录，校验完整的九项 checksum 后，再解压目标 archive 中唯一的规范根目录库文件：

```bash
sha256sum -c checksums.txt
unzip privacyfilter_0.3.5_linux_amd64.zip
```

Archive 恰好包含一个 `privacyfilter.so`（macOS 为 `.dylib`，Windows 为 `.dll`），mode 为 `0755`，ZIP 时间戳固定。Release 还包含 `release-manifest.json`、`NOTICE`、`LICENSE` 和 `THIRD_PARTY_LICENSES.md`。

只把校验过的库放入宿主 native plugin discovery 目录。不要复制本地开发 build 或历史遗留且被忽略的 `dist/privacyfilter.so`。Linux 上 Go shared library 使用 `DF_1_NODELETE` 加载，因此加载、替换或移除插件后都必须重启 CLIProxyAPI 进程。

宿主的全局 plugin subsystem 必须已启用，并且该库必须处于 effective enabled 状态。已发现但没有 config stanza 的库是否自动启用取决于宿主版本；应检查经过字段白名单投影后的 management 状态，不能假设发现即执行。本 Release gate 使用的官方 v7.3.4 精确镜像会发现但禁用未配置的库，因此该版本要求显式启用。最小宿主 stanza 为：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
```

不配置插件自有选项时，privacyfilter 默认使用 `mode: redact`、`on_error: block`、内嵌规则、空 block/skip 列表和下方有界限制。`enabled` 和 `priority` 是宿主字段；其宿主默认 priority 为 `0`。运维可以调整 priority 或插件选项，但必须根据所有 request interceptor 验证实际顺序；每个 interceptor 阶段中，priority 越低越晚执行。

## 配置说明

完整的插件自有配置示例：

```yaml
mode: redact                    # redact | tokenize | audit
on_error: block                 # block | passthrough

key_filter:                     # 两个列表都为空时不生效
  mode: include                 # include | exclude
  api_keys: []                  # 明文客户端 API key，加载时取哈希
  caller_scopes: []             # 或预先计算好的 64 位十六进制调用方标识
  on_missing_identity: filter   # filter | skip

tokenize:                       # 仅 mode: tokenize 使用
  token_format: "pf-{kind}-{hash12}"
  hmac_secret: ""               # 为空 = 每个进程随机生成
  max_entries: 100000
  ttl: 1h
  restore_scope: caller         # caller | request

gitleaks_toml: ""              # 为空时始终使用 pinned 内嵌规则
# gitleaks_mode: extend         # extend | replace；需要 gitleaks_toml
allow_unsupported_rules: false
block_rule_ids: []

replacements:
  email: "[EMAIL]"
  phone: "[PHONE]"
  id_card: "[ID_CARD]"
  bank_card: "[BANK_CARD]"
  ip: "[IP_ADDRESS]"
  secret: "[SECRET]"

skip_models: []                 # 显式 break-glass 绕过
skip_formats: []

limits:
  max_body_bytes: 33554432
  max_depth: 128
  max_json_nodes: 250000
  max_structural_bytes: 134217728
  max_string_bytes: 8388608
  max_replacements: 100000
  max_replacement_bytes: 33554432
  max_text_bytes: 33554432
  max_text_nodes: 100000
  max_findings: 4096
```

配置使用严格 YAML 解码。未知字段（包括 `key_filter` 和 `tokenize` 内部）、重复的映射键、非法枚举值、重复 blocking rule ID、重复或为空的 `key_filter` 条目、格式错误的 `token_format`、不安全 replacement、多份 YAML document，或超过 hard maximum 的限制都会导致注册失败。错误信息不会回显 API key、调用方标识或 `hmac_secret`。

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `mode` | `redact` | 脱敏 finding。`tokenize` 把 finding 替换为会在响应中还原的 token。`audit` 只统计，不改写，也不执行基于 rule 的拒绝；检查错误仍遵循 `on_error`。 |
| `key_filter` | 不生效 | 只对列出的客户端 API key（`include`）或除它们之外的全部 key（`exclude`）启用过滤。见下文。 |
| `tokenize` | 如上 | `mode: tokenize` 的 token 格式、HMAC secret、vault 上限和还原范围。见下文。 |
| `on_error` | `block` | 主动终止检查失败。`passthrough` 是显式 fail-open 绕过。 |
| `gitleaks_toml` | `""` | 自定义 TOML 路径。为空时始终使用内嵌规则，绝不会读取相邻 sidecar。 |
| `gitleaks_mode` | 未设置 | 指定自定义文件时，未设置保留旧版 replace 行为；也可显式设为 `extend` 或 `replace`。 |
| `allow_unsupported_rules` | `false` | 拒绝自定义规则中的不支持语义；`true` 允许跳过并明确报告。 |
| `block_rule_ids` | `[]` | Redact 模式下，命中这些精确 rule ID 时以 422 终止，而不是替换。 |
| `replacements` | 类型化默认值 | 覆盖六种 placeholder；空字符串表示删除命中值。 |
| `skip_models` / `skip_formats` | `[]` | 可信且显式的完整检查绕过。先于 `key_filter` 判断。 |
| `limits` | 如上 | 请求级上限。Payload 字段为零时使用有界默认值，detector 字段必须为正；所有值都不能超过对应 hard maximum。 |

内嵌快照是 Gitleaks v8.30.0 在 commit `6eaad039603a4de39fddd1cf5f727391efe9974e` 的精确默认配置，SHA-256 为 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`。其中 222 条规则可见、217 条加载；4 条 path-constrained 规则和 1 条 path-only 规则被跳过；另有 4 项 path allowlist 条件因协议文本没有文件路径而被忽略。精确的九项兼容性报告或文件字节一旦变化，注册就会失败。可运行 `scripts/update-rules.sh --check` 验证本地快照；更新命令只获取该不可变 commit，并校验预期 digest。

## 只对指定 API key 启用过滤

`key_filter` 让插件只处理使用特定下游客户端 key 认证的请求，即 CLIProxyAPI 配置顶层 `api-keys` 中的 key。其他请求按原始字节直接放行。

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
      key_filter:
        mode: include
        api_keys:
          - "sk-my-private-key"
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `mode` | `include` | `include` 只检查列出的 key；`exclude` 检查除列出的 key 之外的所有 key。 |
| `api_keys` | `[]` | 明文客户端 API key。加载配置时逐个取哈希，不保留明文。 |
| `caller_scopes` | `[]` | 同样的身份，以预先计算好的标识给出，适合不希望在插件配置中出现明文 key 的场景。 |
| `on_missing_identity` | `filter` | 选定上游凭证之后，宿主仍未提供调用方身份时的处理方式。`filter` 检查（fail closed）；`skip` 放行。 |

两个列表都为空表示 key 过滤关闭，所有请求都会被检查，与没有该配置段完全相同。只设置 `mode` 或 `on_missing_identity` 不会使其生效。

**如何匹配 key。** 宿主不会把原始 API key 交给 interceptor，而是提供 `caller_scope`：对 `cli-proxy-api:caller-scope:v1`、一个 NUL 字节、去除首尾空白后的 key 依次拼接后计算 SHA-256，取小写十六进制。插件对 `api_keys` 的每一项做同样的计算，然后比较标识。如果想填写标识而不是 key，只需计算一次：

```bash
printf 'cli-proxy-api:caller-scope:v1\0%s' 'sk-my-private-key' | sha256sum
```

把得到的 64 位十六进制字符填入 `caller_scopes`。两个列表可以同时使用；同一身份无论以哪种形式出现两次都会被拒绝。

**判断顺序。** 每次 interceptor 调用依次执行：

1. `skip_models` / `skip_formats`：命中即绕过检查，与 key 无关。
2. `key_filter`：如果生效，由调用方身份决定检查还是放行。
3. 按配置的 `mode` 检查，包括 `block_rule_ids`、`on_error` 和 `ml_assist`。

因此只有在没有命中任何 skip **并且** key 过滤选中该请求时才会检查。被 key 过滤放行的请求不会被改写，也不会被拒绝（即使请求体格式错误）；在 `mode: tokenize` 下，该请求及其响应都不会被处理。

**Interceptor 阶段。** 宿主在选定上游凭证之前和之后各调用一次 request interceptor。调用方身份来自客户端认证，早于这两次调用，因此通常在第一次调用时就能做出决定。如果在选定凭证之前没有身份，插件在该阶段什么都不做；选定凭证之后按 `on_missing_identity` 处理。用于在第二次调用时识别已检查请求体的请求缓存照常工作。

**日志。** 不记录 key 和调用方标识。注册时记录模式和已配置身份的数量。Debug 级别下每次决定记录为 `filtered` 或 `skipped_by_key`，并附带累计计数。

**限制。**

- `key_filter` 是又一条绕过过滤的途径。来自未列出 key（`exclude` 时为已列出 key）的请求会未经检查到达上游，与 `skip_models` 相同。
- 它只覆盖会经过 request interceptor 的模型执行请求，对 `/v1/models`、management 路由以及其他不经过 interceptor 的端点没有影响。
- 匹配依赖 pinned SDK 中宿主的 `caller_scope` 计算方式。如果某个宿主版本改变了它，明文 `api_keys` 将不再匹配：`include` 列表会什么都不过滤，`exclude` 列表会过滤全部请求。每次升级宿主后都应重新验证。
- 如果关闭了客户端认证，就完全没有身份；此时所有请求都按 `on_missing_identity` 处理。
- 通过 management 面板填写的 key 会在面板中以明文显示，与 `config.yaml` 中一样。可改用 `caller_scopes` 避免。

## 可逆 token 化（`mode: tokenize`）

在该模式下，命中值会被替换为形如 `pf-secret-3f9a1c0b7d2e` 的 token。模型能看到 token，并可以把它用在代码、命令和配置中。响应到达客户端之前，插件再把 token 替换回原始值。上游始终拿不到原始值。

```yaml
mode: tokenize
tokenize:
  token_format: "pf-{kind}-{hash12}"
  hmac_secret: ""
  max_entries: 100000
  ttl: 1h
  restore_scope: caller
```

| 字段 | 默认值 | 说明 |
|---|---|---|
| `token_format` | `pf-{kind}-{hash12}` | 字面部分只能使用 `[a-z0-9-]`，因此 token 永远不需要 JSON 转义。`{hashN}`（N 为 8 到 64）必须且只能出现一次；`{kind}` 可选，展开为 `email`、`phone`、`idcard`、`bankcard`、`ip` 或 `secret`。 |
| `hmac_secret` | `""` | Token MAC 的密钥，16 到 1024 字节。为空时每个进程生成一次随机密钥。 |
| `max_entries` | `100000` | 所有调用方合计的 token 到原始值映射数量上限（hard maximum 为 1,000,000）。超出时先淘汰最久未使用的映射。 |
| `ttl` | `1h` | 映射的滑动存活时间，每次签发或还原该 token 时刷新（1s 到 168h）。同时也是响应会话的空闲存活时间。 |
| `restore_scope` | `caller` | 响应可以还原哪些 token：签发给同一客户端 API key 的（`caller`），或只限为同一请求签发的（`request`）。 |

**Token 是确定性的。** Token 为 `HMAC-SHA256(hmac_secret, 调用方身份, kind, 值)` 截断到 N 位十六进制。在 secret 不变的前提下，同一 API key 的同一值总是得到同一 token，从而保持多轮对话和上游 prompt caching 稳定。`hmac_secret` 为空时密钥按进程随机生成，因此**重启后 token 会变化**（插件 reconfigure 会保留密钥）。如果 token 需要跨重启保持不变，请设置 `hmac_secret`，并像对待其他 secret 一样保护它；修改它会改变所有 token。由于调用方身份参与 MAC，两个 API key 对同一值得到的 token 互不相关。

**还原是隔离的。** 映射按调用方（或按请求）分区保存，响应只查询自己的分区。如果有人把其他调用方的 token 写进 prompt 并让模型原样重复，该 token 会原样返回，并计入 `unresolved`。使用 `restore_scope: caller` 时，共用同一 API key 的所有客户端属于同一信任域：在一次对话中签发的 token 可以在同一 key 的另一次对话中被还原。这正是服务端历史（例如 Responses 的 `previous_response_id`）能够工作的原因。`restore_scope: request` 取消这一点：响应只还原为本请求签发的 token，请求结束时映射即被销毁。没有经过认证的调用方身份的请求始终使用 request 范围。

**存储。** 映射只存在于进程内存中，受 `max_entries` 和 `ttl` 约束，不会写入磁盘或日志。宿主报告请求完成时（包括客户端取消和上游失败），响应侧缓冲区会被释放；request 范围下映射本身也会被释放。Shutdown 以及离开 `mode: tokenize` 的 reconfigure 都会清空全部内容。

**还原哪些内容。** 只还原完全匹配的 token。被模型改动过的 token（大小写不同、被截断、被编辑）不会被猜测。支持的响应格式为 `openai`、`openai-response`、`claude`、`gemini` 和 `interactions`：

- 非流式：所有 JSON 字符串值，包括 tool call arguments、`tool_use.input`、Gemini `functionCall.args` 和 structured output。本身包含 JSON 文档的字符串会深入一层还原，原始值先按内层字符串转义，再按外层字符串转义。不含 token 的字节不会被改写。
- 流式：`delta.content` 和 `tool_calls[].function.arguments`、`response.output_text.delta` 及 function/custom tool 的 arguments delta、`content_block_delta`（`text_delta`、`input_json_delta`）、Gemini 文本 part，以及 Interactions `step.delta`。每个 block 或 tool call 有独立的缓冲区。被切分到多个 chunk 的 token 会被重新拼接：插件只暂扣可能仍会成为 token 的尾部片段（最多比 token 少一个字节），一旦不再匹配就立即放出。Block 结束时，暂扣的尾部会被并入带有 `finish_reason` / `finishReason` 的 chunk，或者在 `content_block_stop`、`step.stop` 或 Responses `*.done` 事件之前以一个额外的 delta 发出。终止事件中的完整字符串（`response.output_text.done`、`response.completed` 等）同样会被还原。

模型的 reasoning 和完整性数据**不会**被还原：`thinking`、`reasoning`、`reasoning_content`、`reasoning_details`、Gemini thought part、签名和 `encrypted_content`。改写带签名的 reasoning 会破坏其 replay，因此 reasoning 记录中可能仍能看到 token。Usage、服务事件和 keep-alive 事件原样通过。

**请求侧。** `block_rule_ids` 和检查错误在任何映射被保存之前判断，因此被拒绝的请求不会留下任何内容。第二次 interceptor 调用时，已经签发给该调用方的 token 会被识别并保持不变；在请求路径上 token 永远不会被还原为原始值。客户端收到还原后的值并作为对话历史再次发送时，只要 detector 在新的上下文中再次命中它，就会得到同一个 token。`mode: tokenize` 与 `key_filter` 可以组合：被 key 过滤放行的请求既不会被 token 化，也不会被还原。

**日志。** 只有计数：请求上的 `tokenized`，以及请求完成时的 `restored`、`unresolved`、`unflushed` 和 `restore_failed`。Token、原始值和 API key 都不会被记录。

**限制。**

- 宿主没有流结束回调，也无法让响应失败。如果流在没有协议终止事件的情况下结束（上游中断），暂扣的尾部（默认格式下最多 23 个字符）不会被发出。尾部只是 token 的前缀，绝不是原始值。该情况计入 `unflushed`。
- 改写响应时出错，会使该响应或该流的剩余部分保留 token 而不是原始值。不会泄露任何内容，但客户端会看到 token。日志中会带 `restore_failed`。
- **Interceptor 顺序。** 宿主按相同的 priority 顺序执行 request 和 response interceptor，并且不会告诉插件有哪些相邻插件。在本插件之前执行的 request interceptor 能看到原始值；在本插件之后执行的 response 或 stream interceptor 能看到还原后的值。要让其他插件在请求侧接触不到明文，本插件必须最先执行，而这也使它在响应侧最先还原；没有任何 priority 能同时满足两者。请把它作为唯一改写 body 的 interceptor 运行，或接受上述两种暴露之一。更早执行并丢弃或重新分帧 chunk 的 response interceptor 也可能使还原失效。该模式下每次注册都会记录一条带有自身 priority 的警告。
- 流式 tool arguments 按 token 所在的字符串字面量转义。如果流式 arguments 的某个字符串中又嵌套了 JSON，其中含引号或反斜杠的值只转义一层。非流式响应可处理最多四层嵌套。
- 流式文本以 `{` 或 `[` 开头并且后续内容持续符合 JSON 语法时，被视为 JSON（structured output）；仅仅以括号开头的普通文本按原样还原。Markdown 代码块中的文本同样按原样还原，因此带引号的值可能使代码块内的 JSON 不合法。
- 在 Responses `*.done` 事件之前发出暂扣尾部的额外 delta 会复用上一个 delta 的 `sequence_number`。
- 显式使用非 SSE `alt` 传输（JSON 数组片段）的 Gemini 流不会被解析；token 保持原样并被上报。
- 如果同一调用方两个不同值的默认 48 位哈希发生碰撞，第二个值会被不可逆脱敏，而不是 token 化。
- 在内存压力（`max_entries`）下或超过 `ttl` 后，映射可能在对话仍引用其 token 时消失；该 token 随后保持未还原。
- 原始值在过期前一直保存在进程内存中。`hmac_secret` 在 management 面板和 `config.yaml` 中可见。

## 失败处理

默认 `on_error: block` 会返回主动终止响应；`on_error: passthrough` 会显式关闭检查错误终止：

| 情况 | HTTP 状态码 |
|---|---:|
| 空请求体或外层 JSON 非法 | 400 |
| 未知格式、不支持/有歧义的协议结构、编码工具 JSON 非法，或在 redact 模式命中配置的 blocking rule | 422 |
| 超过 body/depth/node/string/structural/detector/finding/replacement 限制 | 413 |
| Native admission 饱和、deadline、插件不可用/正在 quiesce、panic 或内部失败 | 503 |

错误体使用对应协议的通用 envelope，不包含命中的请求值。

## 信任边界与限制

本插件是有界的请求体 defense-in-depth 层，**不是绝对的最终 egress DLP 边界**。以下宿主顺序观察基于 SDK v7.2.157，并且必须在每个 Release manifest 所记录的精确 image 上重新验证：

1. CLIProxyAPI 的入口 middleware 和 router 会在 request interceptor 之前看到原始请求；更早执行的可信进程内插件也可以看到它。
2. 官方宿主可能在插件处理前，把被拒绝请求的原始 body 持久化到本地 forced-error log。应保护宿主和日志访问；如果本地落盘脱敏是硬性要求，应使用 pre-ingress scrubber 或宿主 pre-log hook。
3. 部分宿主 translation/normalization 发生在 request interceptor 之后。本插件只覆盖 interceptor 阶段识别到的 body，不覆盖后续 translator 新生成的文本。真正的最终 egress 保证需要宿主提供 post-translation hook，或使用独立 egress proxy。
4. 不过滤模型响应、SSE/流式输出和响应侧工具输出。`mode: tokenize` 改写它们只是为了把原始值放回去。
5. 不解码二进制和引用内容：图片、音频、视频、PDF/Office、inline/base64 数据及远程文件不会经过 OCR 或文档提取。
6. 协议分类表是 pinned 的。新增含字符串字段在完成审查和支持前可能返回 422。
7. 检测仍是启发式的。精确凭证字段有意避免宽泛子串匹配；通用 detector 仍可能误报或漏报。
8. `skip_models`、`skip_formats`、`key_filter`、`on_error: passthrough` 和 `mode: audit` 都是显式安全绕过。

## 构建与验证

本地 native build 仅用于 staging：

```bash
git clone https://github.com/ahoo/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
# dist/staging/<goos>-<goarch>/privacyfilter.<extension>
```

Build 使用 `GOFLAGS=-mod=readonly`，并嵌入 VCS metadata、版本和源码 revision。Linux Release job 使用 `.github/workflows/build.yml` 中 pinned 的 Debian Bookworm image，不会发布源码树中的开发 ELF。

常用源码 gate：

```bash
gofmt -w $(git ls-files '*.go')
go mod verify
GOFLAGS='' go mod tidy -diff
go vet ./...
go vet ./.github/scripts
go test ./...
go test ./.github/scripts
go test -race ./...
go test ./... -count=2
python3 -m unittest discover -s .github/scripts -p 'test_*.py'
./scripts/test-native-abi.sh
./scripts/update-rules.sh --check
./.github/scripts/generate-license-report.py --check
go test ./payload -run='^$' -fuzz='^FuzzScanNoPanic$' -fuzztime=15s
go test ./internal/privacyengine -run='^$' -fuzz='^FuzzNoPanic$' -fuzztime=15s
go test . -run='^$' -fuzz='^FuzzStreamRestoreRandomSplits$' -fuzztime=15s
```

Release workflow 只发布五个平台：Linux amd64/arm64、Darwin amd64/arm64 和 Windows amd64。Workflow 使用 pinned Actions，拒绝覆盖已存在的 Release，不使用 `--clobber`，并在发布前校验 tag/version/main 完全一致。

## 来源与许可证

- 原始插件及历史：[rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- 加固分支：[ahoo/cpa-plugin-privacyfilter](https://github.com/ahoo/cpa-plugin-privacyfilter)
- 协议安全 scanner 改编：[ToS0/cpa-plugin-privacyfilter](https://github.com/ToS0/cpa-plugin-privacyfilter)
- Detector 来源：[PackyMe/privacy-filter](https://github.com/PackyMe/privacy-filter)
- 内嵌规则：[Gitleaks](https://github.com/gitleaks/gitleaks)
- Plugin SDK：[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- `key_filter` 和 `mode: tokenize` 的设计参考（未复制代码）：[DoingDog/cpa-plugin-censorship](https://github.com/DoingDog/cpa-plugin-censorship)、[szxypi/cpa-plugin-privacyfilter](https://github.com/szxypi/cpa-plugin-privacyfilter)、[jianhongyu136/plugin-privacy-filter](https://github.com/jianhongyu136/plugin-privacy-filter)

本仓库使用 MIT 许可证。精确 provenance、版权、源码 commit 和链接依赖许可证见 [LICENSE](LICENSE)、[NOTICE](NOTICE) 和 [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md)。
