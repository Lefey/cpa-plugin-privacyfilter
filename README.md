# CPA Plugin Privacy Filter

English | [简体中文](README.zh-CN.md)

A protocol-aware, request-side privacy filter for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). It irreversibly
redacts selected PII and credentials before supported request text is sent to a
provider. Requests that cannot be inspected safely are actively terminated by
default. Two opt-in features build on that: [`key_filter`](#restricting-the-filter-to-selected-api-keys)
applies the filter only to chosen client API keys, and
[`mode: tokenize`](#reversible-tokenization-mode-tokenize) replaces values with
tokens that are turned back into the original values in the provider response.

> **Do not install the official Plugin Store entry named `privacyfilter`.** As
> of 2026-09-15, that [Store record](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store/blob/main/registry.json)
> is owned by `rheodev` and resolves to their older v0.2.0 implementation. This
> `ahoo` fork deliberately does not claim a second Store identity. Install only
> a checksum-verified artifact from this repository's immutable Releases.
>
> Do not install `v0.3.0`: its artifact set passed the release gates, but it was
> published before repository release immutability was enabled. `v0.3.1` remained
> an unpublished draft after its publication workflow failed closed. `v0.3.2` was
> the first immutable Release. The `v0.3.3` publication gate failed closed before
> creating a Release because its expanded exact-Host assertion set was not yet in
> the release-manifest validator. `v0.3.4` carries the Responses Lite/Codex
> compatibility fix and the matching validator update. `v0.3.5` adds validated
> OpenRouter `reasoning_details` replay compatibility and value-free rejection
> diagnostics. Install a version only after GitHub marks its Release immutable,
> and only from its checksum-verified artifacts. Never install a source-tree or
> development build; verify the exact version and filenames before following the
> examples below.

## Security model

- Understands OpenAI Chat Completions, OpenAI Responses, Anthropic Messages,
  Gemini GenerateContent, and Interactions request shapes.
- Inspects model-visible system, user, assistant/replay, tool input/output,
  tool-description, and tool-schema text that the supported walkers explicitly
  classify.
- Redacts common PII, Gitleaks-style secrets, and short values under exact,
  high-confidence credential fields in structured tool data.
- Rewrites only selected JSON string values. Object keys are never rewritten.
  Untouched whitespace, member order, duplicate keys, escapes, and numeric
  lexemes remain byte-for-byte unchanged.
- Uses request-local irreversible placeholders. Equal values reuse a placeholder
  inside one logical request; distinct values of the same type are numbered.
  Only placeholders actually produced by that request are trusted on a second
  interceptor pass.
- Assigns every string in a recognized protocol object one explicit disposition:
  sanitizable, enumerated opaque control/integrity data, or unsupported. Unknown
  string-bearing extensions fail closed instead of being silently skipped.
- Defaults to `mode: redact`, `on_error: block`, embedded rules, no model/format
  bypasses, and no blocking rule IDs.
- Uses RPC schema 2 active termination. A rejected request is returned as a
  successful plugin RPC envelope with `Terminate: true`, so it is not forwarded
  merely because ordinary interceptor errors are fail-open in the Host.
- Logs counts, constant failure categories, and bounded allowlisted schema paths
  only. Unknown object keys are rendered as `<redacted>`; the plugin does not log
  matched values, error details, or request bodies.

The default `mode: redact` is **irreversible redaction**: the plugin does not
retain original values. Only the opt-in `mode: tokenize` keeps a bounded,
in-memory mapping so that it can restore values in the response; see
[Reversible tokenization](#reversible-tokenization-mode-tokenize).

## Supported request formats

`SourceFormat` matching is exact:

| `SourceFormat` | Request schema | Inspected data |
|---|---|---|
| `openai` | Chat Completions | message text, multipart text, legacy/current function arguments, tool-role output, function descriptions and parameter schemas; validated OpenRouter `reasoning`/`reasoning_content`/`reasoning_details` replay remains opaque and byte-preserved |
| `openai-response` | Responses | instructions, input/replay text, prompt variables, Responses Lite `additional_tools`, function/custom/namespace/tool-search/web-search definitions, current tool history, function descriptions and input/output schemas, text-format schemas, and encoded Codex turn metadata |
| `claude` | Anthropic Messages | top-level system, message text, `tool_use.input`, string/structured `tool_result.content`, tool descriptions and input schemas |
| `gemini` | Gemini GenerateContent | system/content text, function arguments/results, executable code/results, display names, function descriptions and parameter/response schemas |
| `interactions` | Interactions | system instruction, nested input/steps/content, function input/output, tool descriptions and schemas |
| `gemini-cli` | Interactions compatibility alias | same handling as `interactions` |

Known control and integrity fields remain opaque: model/role/type discriminators,
tool names and IDs, call IDs, status values, signatures, encrypted reasoning,
validated provider reasoning replay (`reasoning`, `reasoning_content`, and the
`reasoning.text`/`reasoning.summary`/`reasoning.encrypted` detail union),
binary/base64 payloads, explicitly enumerated URL/file references, and flat
Codex `client_metadata` transport/session values. The encoded
`x-codex-turn-metadata` object and additive unknown metadata are recursively
inspected rather than causing a compatibility 422; known flat transport IDs
remain opaque.
Unsupported Responses root-tool variants are rejected rather than forwarded
opaquely.

### Structured credential fields

Within recognized structured tool input/output, non-empty non-template strings
under exact credential names are wholly redacted even when short or low-entropy.
Supported exact families include:

- `AK`, `SK`, `api_key`, `api_secret`, `api_secret_key`;
- `access_key`, `access_key_id`, `secret_key`, `secret_access_key`;
- AWS access/secret-key names, `client_secret`, and `private_key`;
- access/API/auth/refresh/session/ID/client/secret/bearer/OAuth token names;
- `password`, `passwd`, `pwd`, `credential`, `secret`, `secrets`, and
  `authorization`.

Keys are ASCII case-folded and `-` is normalized to `_`, within a 64-byte key
bound. Matching is exact after normalization; concatenated entries such as
`apikey` and `accesskeyid` cover their camelCase forms. `AK` and `SK` trigger
whole-value handling only as the immediate field name; unlike the longer,
less-ambiguous credential names, they do not propagate to descendant strings.
This preserves ordinary structures such as DynamoDB `{"SK":{"S":"..."}}`
while still redacting `{"SK":"..."}`. This is an exact allowlist, not
substring matching: `monkey`, `token_id`, `api_key_name`, `secret_name`,
`client_id`, and arbitrary `MY_SECRET_KEY`-style names do not trigger the
whole-field rule by name alone. Generic secret and PII detectors still inspect
their values. Template variables and recognized mask placeholders remain
unchanged.

## Detection and placeholders

The engine combines:

- email addresses;
- mainland China phone and ID-card numbers;
- Luhn-valid bank-card numbers;
- IPv4 addresses;
- contextual and high-entropy secret detection;
- exact structured credential-field detection; and
- the request-text-compatible regex, keyword, entropy, capture-group, and
  allowlist subset of the pinned Gitleaks snapshot.

Default placeholders are:

| Kind | First distinct value | Second distinct value |
|---|---|---|
| `email` | `[邮箱]` | `[邮箱#2]` |
| `phone` | `[电话]` | `[电话#2]` |
| `id_card` | `[身份证]` | `[身份证#2]` |
| `bank_card` | `[银行卡]` | `[银行卡#2]` |
| `ip` | `[IP]` | `[IP#2]` |
| `secret` | `[密钥]` | `[密钥#2]` |

The embedded rules recognise machine-looking secrets. A short human password
written in prose, such as `my password is passW0RD!`, is not one of them. The
optional [`rules/prose-credentials.toml`](rules/prose-credentials.toml) adds
that: copy it next to the plugin library and set `gitleaks_toml` to its path
with `gitleaks_mode: extend`. It catches a value next to `пароль`, `секрет`,
`токен`, `ключ`, `password` or `passwd` when the value is quoted, or is at
least six characters long and contains a digit or one of `!@#%^&*`. A
credential stated without one of those words nearby is still not detected.

The request cache retains only hashes and replacement labels. It never retains a
plaintext finding or a reversible mapping. In `mode: tokenize` a separate token
vault does hold original values in memory; it is described below.

## Fixed resource bounds

The following hard maxima cannot be raised or disabled by configuration:

| Resource | Hard maximum |
|---|---:|
| Native RPC envelope | 64 MiB |
| Request body | 32 MiB |
| JSON depth | 128 |
| JSON values, outer and encoded JSON combined | 250,000 |
| Conservatively accounted scanner/walker structure | 128 MiB |
| One decoded string or replacement | 8 MiB |
| Replacements | 100,000 |
| Encoded replacement output | 32 MiB |
| Cumulative detector text | 32 MiB |
| Detector text nodes | 100,000 |
| Findings | 4,096 |
| Concurrent native scans | 4 |
| Native admission wait | 100 ms |
| Native inspection deadline | 10 s |

JSON containers carried by scalar, typed/list, or native structured string
fields in recognized tool input/output are inspected recursively. Encoded and
recursively encoded tool JSON shares the outer request's node, structural,
detector, finding, and replacement budgets. Recursion is additionally capped at
four nested encoded containers. Native work stays synchronous so no
scanner goroutine survives a returned request. The C ABI cannot propagate client
cancellation; it uses its internal deadline and checks cancellation between
bounded scan operations. A single in-progress Go regular-expression operation is
not forcibly interrupted.

Configuration may lower, but never raise, these hard maxima. A zero payload
scan/replacement limit selects its bounded default; detector limits must be
positive.

## Requirements

- An official CLIProxyAPI build with native plugin ABI 1. Full fail-closed
  behavior requires Host RPC schema 2 or newer; the plugin negotiates schema 2.
  On a schema-1 Host, registration fails when `on_error: block` or any
  `block_rule_ids` are configured.
- `mode: tokenize` additionally registers the response and stream-chunk
  interceptors and negotiates Host RPC schema 5, so that the Host stops
  resending the request body and chunk history with every stream chunk. On an
  older Host it still works, at the negotiated schema, with that per-chunk
  overhead. No other mode changes the registration.
- The plugin is compiled against CLIProxyAPI SDK v7.2.157. A release must not be
  published until its manifest records the exact official Host image and digest
  used by the isolated integration gate.
- Go 1.26 and CGO when building from source.
- A native C toolchain for the target platform.

## Installation

Download all assets from the same immutable Release into a fresh directory,
verify the complete nine-entry checksum set, then extract the target archive's
one canonical root library:

```bash
sha256sum -c checksums.txt
unzip privacyfilter_0.3.5_linux_amd64.zip
```

The archive contains exactly `privacyfilter.so` (`.dylib` on macOS, `.dll` on
Windows), mode `0755`, with a fixed ZIP timestamp. Release metadata also includes
`release-manifest.json`, `NOTICE`, `LICENSE`, and `THIRD_PARTY_LICENSES.md`.

Place only the verified library in the Host's native-plugin discovery directory.
Do not copy a local development build or the historical ignored
`dist/privacyfilter.so`. Loading, replacing, or removing a Go shared library
requires restarting the CLIProxyAPI process because Go shared libraries are
loaded with `DF_1_NODELETE` on Linux.

The Host's global plugin subsystem must be enabled, and the library must be
effectively enabled. Whether a discovered library without a config stanza is
enabled is Host-version-specific; verify the projected management state rather
than assuming discovery implies execution. The exact official v7.3.4 image used
by this release gate discovers but disables an unconfigured library, so it
requires explicit enablement. A minimal Host stanza is:

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    privacyfilter:
      enabled: true
```

With no plugin-owned options, privacyfilter itself defaults to `mode: redact`,
`on_error: block`, embedded rules, empty block/skip lists, and the bounded limits
shown below. `enabled` and `priority` are Host-owned settings; their Host default
is priority `0`. An operator may change priority or plugin-owned options, but
should verify ordering against every other request interceptor. Lower priority
runs later in each interceptor stage.

## Configuration reference

A complete plugin-owned example is:

```yaml
mode: redact                    # redact | tokenize | audit
on_error: block                 # block | passthrough

key_filter:                     # inactive while both lists are empty
  mode: include                 # include | exclude
  api_keys: []                  # client API keys in plaintext, hashed at load
  caller_scopes: []             # or precomputed 64-hex caller identifiers
  on_missing_identity: filter   # filter | skip

tokenize:                       # used only by mode: tokenize
  token_format: "pf-{kind}-{hash12}"
  hmac_secret: ""               # empty = random per process
  max_entries: 100000
  ttl: 1h
  restore_scope: caller         # caller | request

gitleaks_toml: ""              # empty always means embedded pinned rules
# gitleaks_mode: extend         # extend | replace; requires gitleaks_toml
allow_unsupported_rules: false
block_rule_ids: []

replacements:
  email: "[EMAIL]"
  phone: "[PHONE]"
  id_card: "[ID_CARD]"
  bank_card: "[BANK_CARD]"
  ip: "[IP_ADDRESS]"
  secret: "[SECRET]"

skip_models: []                 # explicit break-glass bypasses
skip_formats: []

ml_assist:                     # distilled second opinion (default off)
  enabled: false
  threshold: 0.5               # validated separation point; within [0,1]
  mode: audit                  # audit counts only; enforce redacts too

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

Configuration uses strict YAML decoding. Unknown fields (including inside
`key_filter` and `tokenize`), duplicate mapping keys, invalid enum values,
duplicate blocking IDs, duplicate or empty `key_filter` entries, a malformed
`token_format`, unsafe replacement strings, multiple YAML documents, or limits
above a hard maximum make registration fail. Errors never echo an API key, a
caller identifier, or `hmac_secret`.

| Field | Default | Meaning |
|---|---:|---|
| `mode` | `redact` | Redact findings. `tokenize` replaces them with tokens that are restored in the response. `audit` counts without mutation or rule-based rejection; inspection errors still follow `on_error`. |
| `key_filter` | inactive | Apply the filter only to (`include`) or to all but (`exclude`) the listed client API keys. See below. |
| `tokenize` | values above | Token format, HMAC secret, vault bounds and restore scope for `mode: tokenize`. See below. |
| `on_error` | `block` | Actively terminate inspection failures. `passthrough` is an explicit fail-open bypass. |
| `gitleaks_toml` | `""` | Custom TOML path. Empty always uses embedded rules and never consults an adjacent sidecar. |
| `gitleaks_mode` | omitted | With a custom path, omitted preserves legacy replace behavior; otherwise explicitly `extend` or `replace`. |
| `allow_unsupported_rules` | `false` | Reject unsupported custom-rule semantics; `true` allows explicitly reported skips. |
| `block_rule_ids` | `[]` | In redact mode, terminate with 422 instead of replacing findings from these exact rule IDs. |
| `replacements` | typed defaults | Override the six placeholder kinds; empty removes the matched value. |
| `skip_models` / `skip_formats` | `[]` | Trusted, explicit inspection bypasses. They are evaluated before `key_filter`. |
| `ml_assist` | disabled | Distilled sensitive-text student rescoring engine-clean texts. `audit` counts `ml_flagged` in logs only; `enforce` also redacts the whole span (downgraded to audit when plugin `mode` is `audit`). Never overrides engine findings. |
| `limits` | values above | Request-wide bounds. Payload zeros select bounded defaults; detector limits must be positive. No value may exceed its hard maximum. |

The embedded snapshot is the exact Gitleaks v8.30.0 default configuration at
commit `6eaad039603a4de39fddd1cf5f727391efe9974e`, SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
It contains 222 rules: 217 load; four path-constrained rules and one path-only
rule are skipped; and four path-allowlist criteria are ignored because protocol
text has no filesystem path. Registration fails if the bytes or the exact
nine-entry compatibility report changes. Run
`scripts/update-rules.sh --check` to verify the local snapshot; the update command
fetches only that immutable commit and checks the expected digest.

## Restricting the filter to selected API keys

`key_filter` applies the plugin only to requests authenticated with particular
downstream client keys, that is, the keys under the top-level `api-keys` of the
CLIProxyAPI configuration. Every other request passes through byte-for-byte.

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

| Field | Default | Meaning |
|---|---|---|
| `mode` | `include` | `include` inspects only the listed keys. `exclude` inspects every key except the listed ones. |
| `api_keys` | `[]` | Client API keys in plaintext. Each is hashed when the configuration loads and is not retained. |
| `caller_scopes` | `[]` | The same identities as precomputed identifiers, for operators who do not want a plaintext key in the plugin stanza. |
| `on_missing_identity` | `filter` | What to do after credential selection when the Host supplied no caller identity. `filter` inspects (fail closed); `skip` passes the request through. |

Both lists empty means the key filter is off and every request is inspected,
exactly as without the section. `mode` and `on_missing_identity` alone do not
activate it.

**How a key is matched.** The Host never hands the raw API key to an
interceptor. It supplies `caller_scope`, the lowercase hexadecimal SHA-256 of
`cli-proxy-api:caller-scope:v1`, one NUL byte, and the trimmed key. The plugin
derives the same value from each `api_keys` entry and compares identifiers. To
list an identifier instead of a key, compute it once:

```bash
printf 'cli-proxy-api:caller-scope:v1\0%s' 'sk-my-private-key' | sha256sum
```

and put the 64 hexadecimal characters under `caller_scopes`. The two lists may
be combined; an identity that appears twice, in either form, is rejected.

**Order of checks.** For every interceptor call:

1. `skip_models` / `skip_formats`: a match bypasses inspection regardless of the
   key.
2. `key_filter`: if active, the caller identity decides between inspecting and
   passing through.
3. Inspection in the configured `mode`, including `block_rule_ids`, `on_error`
   and `ml_assist`.

A request is therefore inspected only if no skip matches **and** the key filter
selects it. A request the key filter passes through is never modified and never
rejected, not even when its body is malformed, and in `mode: tokenize` neither
it nor its response is touched.

**Interceptor stages.** The Host calls a request interceptor before and after
it selects the upstream credential. The caller identity comes from client
authentication, which precedes both calls, so the decision is normally made at
the first one. If the identity is absent before credential selection, the
plugin does nothing at that stage; after credential selection it applies
`on_missing_identity`. The request cache that recognises an already inspected
body on the second call works as before.

**Logging.** Keys and caller identifiers are never logged. Registration logs
the mode and the number of configured identities. At debug level each decision
is logged as `filtered` or `skipped_by_key` together with running totals.

**Limitations.**

- `key_filter` is one more way around the filter. A request from an unlisted
  key (or, with `exclude`, a listed one) reaches the provider uninspected, the
  same as `skip_models`.
- It covers model-execution requests that reach the request interceptors. It
  has no effect on `/v1/models`, management routes, or any other endpoint that
  does not go through them.
- Matching depends on the Host's `caller_scope` derivation in the pinned SDK. If
  a Host release changes it, plaintext `api_keys` stop matching: an `include`
  list then filters nothing and an `exclude` list filters everything. Revalidate
  after every Host upgrade.
- If client authentication is disabled there is no identity at all; every
  request then follows `on_missing_identity`.
- Keys entered through the management panel are shown there in plaintext, as
  they are in `config.yaml`. Use `caller_scopes` to avoid that.

## Reversible tokenization (`mode: tokenize`)

In this mode a detected value is replaced with a token such as
`pf-secret-3f9a1c0b7d2e`. The model sees and can reuse the token in code,
commands and configuration. Before the response reaches the client, the plugin
replaces the token with the original value again. The provider never receives
the value.

```yaml
mode: tokenize
tokenize:
  token_format: "pf-{kind}-{hash12}"
  hmac_secret: ""
  max_entries: 100000
  ttl: 1h
  restore_scope: caller
```

| Field | Default | Meaning |
|---|---|---|
| `token_format` | `pf-{kind}-{hash12}` | Literal text may use only `[a-z0-9-]`, so a token never needs JSON escaping. `{hashN}` (N from 8 to 64) is required exactly once; `{kind}` is optional and expands to `email`, `phone`, `idcard`, `bankcard`, `ip` or `secret`. |
| `hmac_secret` | `""` | Key for the token MAC, 16 to 1024 bytes. Empty selects a random key generated once per process. |
| `max_entries` | `100000` | Upper bound on stored token-to-value mappings across all callers (hard maximum 1,000,000). The least recently used mapping is evicted first. |
| `ttl` | `1h` | Sliding lifetime of a mapping, refreshed whenever the token is issued or restored (1s to 168h). It is also the idle lifetime of a response session. |
| `restore_scope` | `caller` | Which tokens a response may resolve: those issued to the same client API key (`caller`) or only those issued for the same request (`request`). |

**Tokens are deterministic.** A token is `HMAC-SHA256(hmac_secret, caller
identity, kind, value)` truncated to N hexadecimal characters. The same value
from the same API key always yields the same token while the secret is
unchanged, which keeps multi-turn conversations and provider prompt caching
stable. With an empty `hmac_secret` the key is random per process, so **tokens
change after a restart** (a plugin reconfigure keeps the key). Set
`hmac_secret` if tokens must survive restarts; treat it like any other secret,
and note that changing it changes every token. Because the caller identity is
part of the MAC, two API keys get unrelated tokens for the same value.

**Restoration is isolated.** Mappings are stored per caller (or per request)
and a response looks up only its own partition. If someone writes another
caller's token into a prompt and asks the model to repeat it, the token comes
back unchanged; it is counted as `unresolved`. With `restore_scope: caller`
every client using one API key is a single trust domain: a token issued in one
conversation can be restored in another conversation under the same key. That
is what makes server-side history (for example Responses
`previous_response_id`) work. `restore_scope: request` removes it: a response
resolves only tokens issued for its own request, and the mappings are destroyed
when the request ends. A request without an authenticated caller always uses
request scope.

**Storage.** Mappings live only in process memory, bounded by `max_entries` and
`ttl`. They are never written to disk or to logs. Response-side buffers and, in
request scope, the mappings themselves are released when the Host reports the
request complete, including client cancellation and upstream failure. Shutdown,
and a reconfigure that leaves `mode: tokenize`, clear everything.

**What is restored.** Only an exact token. A token the model altered (different
case, truncated, edited) is not guessed at. Supported response formats are
`openai`, `openai-response`, `claude`, `gemini` and `interactions`:

- Non-streaming: every JSON string value, including tool-call arguments,
  `tool_use.input`, Gemini `functionCall.args` and structured output. A string
  that itself contains a JSON document is restored one level down, so the value
  is escaped correctly for the inner string and again for the outer one. Bytes
  that carry no token are not rewritten.
- Streaming: `delta.content` and `tool_calls[].function.arguments`,
  `response.output_text.delta` and function/custom-tool argument deltas,
  `content_block_delta` (`text_delta`, `input_json_delta`), Gemini text parts,
  and Interactions `step.delta`. Each block or tool call has its own buffer. A
  token split across chunks is reassembled: the plugin withholds only a trailing
  run that could still become a token (at most one byte less than a token) and
  releases it as soon as it stops matching. When a block ends, a withheld tail
  is merged into the chunk that carries `finish_reason` / `finishReason`, or
  sent as one extra delta just before `content_block_stop`, `step.stop` or the
  Responses `*.done` event. Complete strings in terminal events
  (`response.output_text.done`, `response.completed`, ...) are restored too.

Model reasoning and integrity data are deliberately **not** restored:
`thinking`, `reasoning`, `reasoning_content`, `reasoning_details`, Gemini
thought parts, signatures and `encrypted_content`. Rewriting signed reasoning
would break its replay. A token may therefore remain visible in a reasoning
trace. Usage, service and keep-alive events are passed through unchanged.

**Requests.** `block_rule_ids` and inspection errors are evaluated before any
mapping is stored, so a rejected request leaves nothing behind. On the second
interceptor call, tokens already issued to the caller are recognised and left
as they are; a token is never turned back into its value on the request path.
A value the client received restored and sends again as conversation history
gets the same token, provided the detector finds it again in its new context.
`mode: tokenize` and `key_filter` compose: a request passed through by key is
neither tokenized nor restored.

**Logging.** Only counters: `tokenized` on the request, and `restored`,
`unresolved`, `unflushed` and `restore_failed` when the request completes.
Tokens, values and API keys are never logged.

**Limitations.**

- The Host offers no end-of-stream callback and no way to fail a response. If a
  stream ends without its protocol's terminal event (upstream abort), a
  withheld tail of at most 23 characters with the default format is not
  delivered. The tail is a prefix of a token, never a value. It is reported as
  `unflushed`.
- An error while rewriting a response leaves that response, or the rest of that
  stream, with tokens instead of values. Nothing leaks, but the client sees the
  token. This is logged with `restore_failed`.
- **Interceptor ordering.** The Host runs request and response interceptors in
  the same priority order and does not tell a plugin about its neighbours. A
  request interceptor that runs before this plugin sees original values; a
  response or stream interceptor that runs after it sees restored values. To
  keep other plugins away from plaintext on the request side this plugin must
  run first, which also makes it restore first on the response side; no
  priority satisfies both. Run it as the only body-rewriting interceptor, or
  accept one of the two exposures. A response interceptor that runs earlier and
  drops or re-frames chunks can also prevent restoration. The plugin logs a
  warning with its own priority at every registration in this mode.
- Streamed tool arguments are escaped for the string literal the token sits in.
  A value with quotes or backslashes inside JSON that is itself nested in a
  string of streamed arguments is escaped one level only. Non-streaming
  responses handle any nesting up to four levels.
- Streamed text is treated as JSON (structured output) while it starts with `{`
  or `[` and keeps following JSON syntax; prose that merely begins with a
  bracket is restored verbatim. Text in a Markdown code fence is also restored
  verbatim, so a value with quotes can make JSON inside the fence invalid.
- The extra delta that delivers a withheld tail before a Responses `*.done`
  event reuses the previous delta's `sequence_number`.
- Gemini streaming with an explicit non-SSE `alt` transport (JSON-array
  fragments) is not parsed; tokens stay in place and are reported.
- If the 48-bit default hash of two different values of one caller collides,
  the second value is redacted irreversibly instead of tokenized.
- Under memory pressure (`max_entries`) or after `ttl`, a mapping can disappear
  while a conversation still refers to its token; the token then stays
  unresolved.
- Original values are held in process memory until they expire. `hmac_secret`
  is visible in the management panel and in `config.yaml`.

## Failure behavior

With the default `on_error: block`, the plugin returns an active termination
response. `on_error: passthrough` explicitly disables error termination:

| Condition | HTTP status |
|---|---:|
| Empty or malformed outer JSON | 400 |
| Unknown format, unsupported/ambiguous protocol shape, malformed encoded tool JSON, or configured blocking rule in redact mode | 422 |
| Body/depth/node/string/structural/detector/finding/replacement limit | 413 |
| Native admission exhaustion, deadline, unavailable/quiesced plugin, panic, or internal failure | 503 |

Error bodies use protocol-appropriate generic envelopes and contain no matched
request values.

## Trust boundaries and limitations

This plugin is a bounded request-body defense-in-depth layer, **not an absolute
final-egress DLP boundary**. The Host-ordering observations below apply to SDK
v7.2.157 and must be revalidated against the exact image recorded for each
Release:

1. CLIProxyAPI's ingress middleware and router can see the raw request before the
   request interceptor runs. Earlier trusted in-process plugins can also see it.
2. The official Host can persist a rejected raw body in local forced-error logs
   before the plugin can sanitize it. Protect Host/log access. If local-at-rest
   redaction is mandatory, use a pre-ingress scrubber or a Host pre-log hook.
3. Some Host translation/normalization happens after request interception. This
   plugin covers the recognized body at its interceptor stage, not text created
   by a later translator. A true final-egress guarantee requires a Host-owned
   post-translation hook or an external egress proxy.
4. Provider responses, SSE streams, and response-side tool output are not
   filtered. `mode: tokenize` rewrites them only to put original values back.
5. Binary/referenced content is not decoded: images, audio, video, PDF/Office,
   inline/base64 data, and remote files receive no OCR or document extraction.
6. Exact protocol tables are pinned. Newly introduced string-bearing fields may
   be rejected with 422 until reviewed and supported.
7. Detection remains heuristic. Exact credential-field coverage intentionally
   avoids broad substring matching; generic detectors can still have false
   positives and false negatives.
8. `skip_models`, `skip_formats`, `key_filter`, `on_error: passthrough`, and
   `mode: audit` are explicit security bypasses.

## Build and verification

Local native builds are staging-only:

```bash
git clone https://github.com/ahoo/cpa-plugin-privacyfilter.git
cd cpa-plugin-privacyfilter
make build
# dist/staging/<goos>-<goarch>/privacyfilter.<extension>
```

`GOFLAGS=-mod=readonly`, VCS metadata, version, and source revision are embedded
in builds. Linux Release jobs use the pinned Debian Bookworm image recorded in
`.github/workflows/build.yml`; they do not publish a source-tree development ELF.

Useful source gates:

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

The release workflow publishes exactly five targets: Linux amd64/arm64, Darwin
amd64/arm64, and Windows amd64. It uses pinned Actions, refuses an existing
Release, never uses `--clobber`, and verifies tag/version/main equality before
publishing.

## Credits and license

- Original plugin and history:
  [rheodev/cpa-plugin-privacyfilter](https://github.com/rheodev/cpa-plugin-privacyfilter)
- Hardened fork: [ahoo/cpa-plugin-privacyfilter](https://github.com/ahoo/cpa-plugin-privacyfilter)
- Protocol-safe scanner adaptations:
  [ToS0/cpa-plugin-privacyfilter](https://github.com/ToS0/cpa-plugin-privacyfilter)
- Detector source: [PackyMe/privacy-filter](https://github.com/PackyMe/privacy-filter)
- Embedded rules: [Gitleaks](https://github.com/gitleaks/gitleaks)
- Plugin SDK: [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
- Design references for `key_filter` and `mode: tokenize` (no code was copied):
  [DoingDog/cpa-plugin-censorship](https://github.com/DoingDog/cpa-plugin-censorship),
  [szxypi/cpa-plugin-privacyfilter](https://github.com/szxypi/cpa-plugin-privacyfilter),
  [jianhongyu136/plugin-privacy-filter](https://github.com/jianhongyu136/plugin-privacy-filter)

This repository is MIT licensed. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for exact provenance,
copyrights, source commits, and linked dependency licenses.
