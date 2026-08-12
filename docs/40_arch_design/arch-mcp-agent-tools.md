---
id: PROJ-ARC-002
layer: L4
feature: mcp-agent-tools
scope: feature
status: Active
upstream: [PROJ-ARC-001]
downstream: []
owner: TakehiroT
updated: 2026-08-12
open_questions: 0
---

# アーキテクチャ設計: MCP Agent Tools

この文書は、[Semantic Dependency Graph CLIのsystem design](arch-dependency-graph-cli-system-design.md)
をAgent hostへ公開するMCP tool contractを定義する。Issue
[#292](https://github.com/TamaT-LLC/depgraph-cli/issues/292)では、長時間処理の
portable baselineであるdurable operation handleを維持したまま、MCP Tasksを
additive extensionとして採用するかを決定する。

## 実装ステータス

| Contract | Decision / version | Status |
| --- | --- | --- |
| MCP SDK | `rmcp 3.1.0` | Fixed |
| Modern MCP protocol | `2026-07-28` | Fixed |
| Portable operation handle | `depgraph-operation-v1` | Required baseline |
| MCP Tasks extension | `io.modelcontextprotocol/tasks` | Option A accepted |
| Agent DTO/schema catalog | `depgraph-mcp-tools-v1` | Issue #295 contract implemented |
| Read-only lifecycle tools | `profile_plan_get`, `daemon_get`, `doctor_get` | Issue #301 implemented through the shared service boundary |
| Graph dependency tools | `graph_dependencies_list`, `graph_dependents_list`, `graph_path_get` | Issue #302 implemented through one pinned snapshot request |
| Graph analysis tools | `graph_impact_get`, `graph_cycles_list`, `graph_unresolved_list` | Issue #303 implemented through shared bounded read services |
| Bounded query/runtime validation | `graph_query`, `runtime_trace_validate` | Issue #304 implemented through prevalidated read-only services |
| Snapshot artifacts | `snapshot_diff_get`, `policy_evaluate`, `graph_export` | Issue #305 implemented through pinned, bounded shared artifact services |
| Runtime store-write | `runtime_trace_import_submit` | Issue #313 implemented through prevalidated durable operation and atomic runtime-snapshot promotion |
| Repository write | `repository_init`, `export_file` | Issue #314 implemented through fixed-root/no-follow service writes and durable atomic file publication |
| Daemon control | `daemon_start_submit`, `daemon_stop` | Issue #315 implemented through shared lifecycle services and durable verified-process orchestration |
| Project execution | `resolve_build_submit` | Issue #316 implemented through the shared build service, verified compiler-pack startup authority, and the existing supervised staging boundary |
| Cross-cutting security E2E | CLI/catalog, capability, path, operation recovery, hostile project execution | Issue #317 implemented through the live stdio profile/path/cancel corpus and the dedicated Linux hostile gate |
| Open questions | `0` | Resolved |

Stage 1ではcontractをfreezeする。operation journal、runner、baseline operation
tools、Tasks adapterの実装は後続taskで行い、この文書のnegotiationとrecovery
semanticsを変更してはならない。

Issue [#295](https://github.com/TamaT-LLC/depgraph-cli/issues/295)は、このStage 1
境界のうち、共通request/envelope、closed Agent DTO、typed error、page/cursor、
portable operation resultとTasks result view、JSON Schema生成を
`crates/depgraph-mcp-tools`へ実装する。MCP transport、tool handler、operation journal、
runner、rmcp adapterは同issueのcontract crateへ含めず、後続taskの責務とする。

生成JSON Schemaはclosed field・tag・scalar boundを検査するstructural preflightであり、
Schema単独の受理をauthorizationやrepository/store accessの根拠にしてはならない。
`returned_items == items.len()`、totalとの大小、source span順序、task時刻/expiryの算術、
`RepositoryRelativePath`や`AgentLocator`を含むUTF-8 byte長はJSON Schema 2020-12で完全には
表現できないため、consumerは必ず
`depgraph-mcp-tools`でDeserializeするか同等のsemantic validationを実施する。
Rust constructor/Deserializerがこれらのauthoritativeなfail-closed境界であり、
schema/Serde差分は回帰testで意図的に固定する。

## Requirement traceability

| ID | Requirement | Resolution |
| --- | --- | --- |
| `FR-003` | outgoing/incoming dependency traversalをAgent hostへ公開する | `DependenciesRequest`を共有service requestとし、direction、one-hop/transitive、`GraphQueryFilter`、traversal limitをCLI/MCPで共有する |
| `FR-004` | bounded graph queryをAgent hostへ安全に公開する | inline queryまたはconfined query fileのexactly-one requestを共有serviceでparse/type-checkし、output admission後にだけpinned snapshotを読む。MCPはclosed query rowをpaged responseとして返す |
| `FR-006` | 二selector間のdependency pathを説明する | `ExplainPathRequest`がcanonical BFS shortest pathを返し、未探索edgeを残す上限到達はpathなしではなく`RESOURCE_EXHAUSTED`とする |
| `FR-008` | repository profile plan previewをread-only lifecycle toolとして公開する | `ProfilePlanRequest`を共有service requestとし、`profile_plan_get`はbounded inline documentまたはconfined repository-relative fileからclosed `AgentProfilePlan`を返す |
| `FR-009` | last daemon statusをprocess制御なしで取得する | `daemon_get`は共有serviceのstatus-file-only readerを呼び、store、daemon lock、process probeを開かない |
| `FR-010` | 長時間処理は切断後もstatus、terminal result、cancelを回収できるdurable handleを返す | baseline operation toolsを全hostに必須とし、Tasksは同じrecordへの追加mappingとする |
| `FR-011` | bounded doctor summary/detailsをAgent hostへ公開する | `DoctorRequest`とclosed `DoctorResponse`を共有し、`doctor_get`はAgent allowlist projectionだけを返す |
| `NFR-001` | Agent-facing executionのinput、output、時間、cancel、concurrencyをboundedにする | service byte/item boundsとcancellation checkを適用し、MCP handlerは既存`RuntimeController`のread deadline、queue/concurrency/rate limit、request cancellation内で実行する |
| `NFR-003` | host差、切断、server restartをfailureとして回収できる | journalをstdio processとrmcp runtimeから独立させ、再接続時に同じIDを解決する |
| `NFR-004` | 同じsnapshot/filterに対するgraph resultを決定的にする | node endpointとedge IDによるcanonical traversal、canonical shortest-path predecessor、snapshot/query-bound cursorで固定する |
| `NFR-005` | public Agent responseからhost-private/raw execution dataを除外する | lifecycle DTOをclosed allowlistとし、worker log、command line、environment、arbitrary properties、absolute root/executable pathを投影しない |
| `Q-002` | baseline handleへMCP Tasksを追加するか | **Resolved: Option Aを採用する** |
| `AC-004` | profile planはworkerまたはproject codeを起動せずcanonical planを返す | static repository inventory plannerだけを呼ぶcore/CLI/process testとproject-code markerで固定する |
| `AC-006` | deps/dependentsのdirection、transitive、filter semanticsがCLIとMCPで一致する | 両frontendを同じ`DepgraphService::dependencies`へroutingし、cross-process edge-ID parity testで固定する |
| `AC-007` | path traversal exhaustionをunreachableと誤認しない | fully explored graphだけが`path_found: false`を返し、未探索edgeがある場合はpartial resultを捨ててtyped resource errorを返す |
| `AC-009` | 不正またはcredential-shaped queryはstore access前に拒否する | parser、credential policy、type checker、service output pre-admissionをsnapshot requestより前に実行し、missing-store testでraw query/literal非反射とstore未作成を検証する |
| `AC-010` | runtime trace validationはgraphを変更せずselected snapshotとのmatchingだけを返す | inline/confined traceをprevalidateしてread-only pinned snapshotへmatchし、store/snapshot/source-tree digest不変をCLI/service/MCP process testで固定する |
| `AC-011` | daemon statusはpublished status fileだけを読み、store/process stateを変更しない | no-follow bounded reader、missing-store test、status/store digest immutability testで固定する |
| `AC-014` | Tasks非対応hostを含め、accepted operationのstatus、result、cancelが未定義分岐なく機能する | capability matrix、result union、認可、再接続、互換性test matrixを本書で固定する |
| `AC-015` | 同じnormalized inputに対するCLIとMCP domain responseを一致させる | lifecycle、query/runtime validation、snapshot diff、policy evaluation、outputなしgraph exportを同じservice methodへroutingし、cross-process parity testでclosed domain resultの一致を検証する |
| `#295` | 共通contract、closed DTO、typed error、pagination、operation型、決定的schema生成 | `depgraph-mcp-tools-v1`のRust型、checked-in schema、digestとcontract golden、およびintegration testで固定する |
| `#301` | profile plan、daemon status、doctorを共有serviceとMCPへ接続する | lifecycle service/DTO/handler、CLI migration、security/redaction/immutability/parity/process test、およびcanonical catalog/schema fixtureで固定する |
| `#302` | dependencies、dependents、explain pathを共有serviceとMCPへ接続する | pinned `SnapshotReadRequest`、closed dependency/path DTO、exact catalog schema、CLI/MCP parity、cursor/exhaustion/process testで固定する |
| `#303` | reverse impact、cycles、unresolved sitesを共有serviceとMCPへ接続する | current-only changed set、cache-independent canonical impact、closed cycle/unresolved DTO、全phaseのbounds/cancellation、snapshot/input-bound cursor、CLI/MCP/process/schema parityで固定する |
| `#304` | bounded queryとruntime validationを共有serviceとMCPへ接続する | pre-store input/output admission、confined file input、pinned read-only snapshot、closed query/runtime DTO、input-bound cursor、CLI/MCP parity、redaction/immutability/process/schema testで固定する |
| `#305` | snapshot diff、policy evaluation、bounded inline graph exportを共有serviceとMCPへ接続する | request開始時のcompleted snapshot pin、canonical policy digest、closed diff/policy/export DTO、inline byte/node/edge bounds、typed `export_file` remediation、CLI/MCP/schema/catalog parityで固定する |
| `#313` | runtime trace importを共有store-write serviceとdurable MCP operationへ接続する | existing validation/matching/delta boundary、writer lock、deferred completion intent、atomic runtime snapshot promotion、closed `AgentRuntimeOutcome`、idempotency/cancel/restart recoveryで固定する |
| `#314` | fixed-root initとrepository-relative file exportを共有repository-write serviceとdurable MCP operationへ接続する | root seal、portable relative path、handle-relative no-follow traversal、same-directory staged fsync/atomic publication、destination precondition、graph store・operation journal・SQLite sidecar・runner purge lockのprotected-state拒否、no-follow/delete-share制約付きrunner guard、closed `AgentExportOutcome`、capability gating、idempotency/cancel/restart recoveryで固定する |
| `#315` | daemon start/stopを共有serviceとdurable MCP operationへ接続する | `Read + StoreWrite + DaemonControl`の閉じたprofile、verified sibling executableのshellなし起動、running/stopped publication後のcompletion intent promotion、closed `AgentDaemonControlOutcome`、idempotency/cancel/restart recoveryで固定する |
| `#316` | resolve buildを共有project-exec serviceとdurable MCP operationへ接続する | `Read + StoreWrite + ProjectExec`の閉じたprofile、`acknowledgement=true`、起動時に再検証したcompiler-pack requirement、staged/neutral supervised execution、source postflight、closed `AgentBuildOutcome`、lease喪失後の非再実行で固定する |
| `#317` | 全CLI mapping、capability、path confinement、operation recovery、hostile project executionを横断検証する | real clap leafとcatalog actionのone-to-one検証、全static profileの実`tools/list` exact matrix、全durable kindのdenied cancel不変性、portable path/symlink/reparse/credential/forged-operation corpus、Tasks/baseline reconnect既存E2E、およびLinux hostile gateのsource/external canary digestで固定する |
| `#318` | MCP server、operation runner、schema、SDK/legal metadataを5 target release closureへ含める | `depgraph-mcp`とrunnerのnative binary、`depgraph-mcp-tools-v1` schema、rmcp compatibility unit、SPDX/license/Apache notice、archive digest、aggregate attestationをfail-closed verifierで固定する |

## Upstream and API evidence

判断は、MCP Tasksのfinal specificationと、crates.ioで配布された`rmcp 3.1.0`
（upstream commit `1f9358eddca42d3a510c70ae6446dd6548c7c856`）に固定する。

- [SEP-2663](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5c4f1768b97198a149d7db05f5026b30c6a3cb12/seps/2663-tasks-extension.md)
  はextension ID、per-request client capability、`CreateTaskResult`、
  `tasks/get`、`tasks/update`、`tasks/cancel`、durable-before-return、polling、
  cooperative cancellation、request単位の認可をnormativeに定義する。
- [`rmcp` capability API](https://github.com/modelcontextprotocol/rust-sdk/blob/1f9358eddca42d3a510c70ae6446dd6548c7c856/crates/rmcp/src/model/capabilities.rs)
  は`ClientCapabilities`と`ServerCapabilities`の`enable_tasks` / `supports_tasks`
  および`io.modelcontextprotocol/tasks` extension mapを提供する。
- [`rmcp` Tasks model](https://github.com/modelcontextprotocol/rust-sdk/blob/1f9358eddca42d3a510c70ae6446dd6548c7c856/crates/rmcp/src/model/task.rs)
  は`CreateTaskResult`、`GetTaskResult`、`DetailedTask`、`TaskStatus`を提供し、
  [`CallToolResponse`](https://github.com/modelcontextprotocol/rust-sdk/blob/1f9358eddca42d3a510c70ae6446dd6548c7c856/crates/rmcp/src/model/mrtr.rs)
  は`Complete | InputRequired | Task`のresult unionを表現できる。
- [`ServerHandler`](https://github.com/modelcontextprotocol/rust-sdk/blob/1f9358eddca42d3a510c70ae6446dd6548c7c856/crates/rmcp/src/handler/server.rs)
  は`get_task`、`update_task`、`cancel_task`を持ち、server/client capabilityを
  検査する。`CallToolResponse::Task`をnon-declaring clientへ返す経路も
  `-32021`で拒否する。
- [`TaskManager`](https://github.com/modelcontextprotocol/rust-sdk/blob/1f9358eddca42d3a510c70ae6446dd6548c7c856/crates/rmcp/src/task_manager.rs)
  はprocess-local `HashMap`とTokio taskを所有し、`shutdown`でtask stateを
  clearする。この実装は単一process内のprotocol conformanceには利用できるが、
  server restart後の回収を満たさないため、depgraphのcanonical persistenceには
  使用しない。

[`rmcp 3.1.0`のprotocol model](https://github.com/modelcontextprotocol/rust-sdk/blob/1f9358eddca42d3a510c70ae6446dd6548c7c856/crates/rmcp/src/model.rs)
では`ProtocolVersion::LATEST`は`2025-11-25`のままで、`2026-07-28`は
`KNOWN_VERSIONS`として提供される。MCP serverはdefault値へ依存せず、modern Tasksを
使う場合はeffective protocolを明示的に`2026-07-28`へnegotiationする。

### Feasibility finding

| Concern | rmcp 3.1.0 evidence | depgraph integration |
| --- | --- | --- |
| Capability | extension mapと`enable_tasks` / `supports_tasks`がある | protocolとper-request client/server declarationを追加でgateする |
| Task creation | `CallToolResponse::Task(CreateTaskResult)`がある | durable journal commit後に`taskId == operation_id`で構築する |
| Retrieval | `ServerHandler::get_task`と`GetTaskResult`がある | journalを`DetailedTask`へread-only mappingする |
| Cancellation | `ServerHandler::cancel_task`とack typeがある | baseline managerでrequired capability setを再認可してcooperative cancelする |
| Reconnection | wire handleは再送できるがSDK managerはprocess-localである | 新server processのhandlerが同じjournalからIDを解決する |

## Q-002 decision

### Compared options

| Criterion | Option A: baseline handle + Tasks | Option B: baseline handle only |
| --- | --- | --- |
| Host compatibility | baselineは不変。negotiated clientだけstandard task pollingを利用できる | 全hostがdepgraph固有operation toolsを使用する |
| Failure recovery | task IDとoperation IDを同一にし、Tasksまたはbaselineのどちらでも同じjournalから回収できる | baselineから回収できるが、Tasks-aware hostのnative lifecycleを利用できない |
| Maintenance | rmcp adapter、status/result mapping、extension conformance testが増える。canonical state machineは一つのまま | protocol surfaceは小さいが、host integrationはすべてcustom contractとなる |
| rmcp 3.1.0 feasibility | 必要なcapability、result union、get/update/cancel APIが存在する。SDK managerの永続性だけを置換する | 実装可能だが、利用可能なofficial extensionを意図的に公開しない |
| Evolution | Tasksがcoreへ昇格してもadapter境界で追従できる | 後から追加するとresult unionとhost conformanceを改めてfreezeする必要がある |

### Decision

**Option A（baseline operation handle + MCP Tasks）を採用する。**

根拠は、Tasksがhost interoperabilityと標準pollingを提供し、`rmcp 3.1.0`が
必要なwire typeとhandler APIを提供済みである一方、追加される永続状態を作る必要が
ないためである。Tasksは`depgraph-operation-v1` recordのviewであり、別のtask store、
別のrunner、別のcancel authorityを持たない。SDKの`TaskManager`はrestart durabilityを
満たさないため使用せず、rmcpはserialization、dispatch、capability guardだけに使う。

Option Aはbaselineをoptionalにしない。Tasksを理解しないhost、legacy protocol、
extensionを宣言しないrequestは、常に同じbaseline operation toolsで回収できる。

## Portable baseline operation contract

### Canonical record and identity

durable toolをsubmitするとき、serverは応答前に次を一つのtransactionとして完了する。

1. normalized input、repository identity、required capability setとdigest、
   idempotency keyを検証する。
2. 128 bit以上のentropyを持つunguessable `operation_id`でjournal recordを作成する。
3. operation recordとrunner handoffをcommitし、直後の別processからread可能にする。
4. negotiated result branchに応じ、同じIDを`OperationAccepted.operation_id`または
   `CreateTaskResult.taskId`として返す。

`taskId == operation_id`を必須とし、二つのIDを結ぶmutable mappingは作らない。
同じrepository、tool、capability、normalized input、idempotency keyのretryは同じ
recordとIDを返す。keyを異なるinputへ再利用した場合は`IDEMPOTENCY_CONFLICT`で拒否する。
status/result/idempotency lookup、submit、cancelのfuture-record検証に使うwall clockは、
SQLite read snapshotまたは`IMMEDIATE` mutation transactionを確定した後にsampleする。
これによりrequest開始後の正当なrunner更新をfuture corruptionと誤認しない一方、clock取得に
失敗した場合はrequest開始時のsampleへfallbackしてfail closedとし、future-record検証自体は
無効化しない。

### Baseline tools

次のtoolsはTasks negotiationと無関係に、serverのstatic capability profileが許す
全hostの`tools/list`へ同じname、description、input/output schemaで現れる。

| Tool | Required access | Semantics |
| --- | --- | --- |
| `operation_get` | 同じrepository identityと`Read` | current status、bounded progress、timestamps、retentionを返す。journalを変更しない |
| `operation_result` | 同じrepository identityと`Read` | terminal時はsubmit toolのclosed output/errorを返す。non-terminal時は`OPERATION_NOT_READY` |
| `operation_cancel` | 同じrepository identityとrecordの全required capabilities | cooperative cancel intentを記録する。terminal recordは成功no-opで変更しない |

Tasks非対応clientへdurable submit toolが返す標準`CallToolResult`の
`structuredContent`は、versioned `OperationAccepted`を含む。単一TextContentはその
canonical JSONとbyte単位で一致する。hostは`operation_id`を保存し、上記三toolだけで
status、terminal result、cancelを回収できる。

## MCP Tasks additive contract

### Capability negotiation and legacy fallback

effective negotiationはprotocol version、server declaration、**そのrequest**のclient
declarationのintersectionで決まる。以前のrequestやsessionで見たcapabilityを今回の
requestへcarry forwardしない。

| Effective protocol | Server extension | Per-request client extension | Submit result | `tasks/*` behavior |
| --- | --- | --- | --- | --- |
| `< 2026-07-28`（`2025-11-25`を含む） | 宣言しない | absentまたは誤ってpresent | baseline `OperationAccepted` | `-32601` Method not found |
| `2026-07-28` | disabled / absent | absentまたはpresent | baseline `OperationAccepted` | `-32601` Method not found |
| `2026-07-28` | `io.modelcontextprotocol/tasks: {}` | absent | baseline `OperationAccepted` | `-32021` Missing Required Client Capability |
| `2026-07-28` | `io.modelcontextprotocol/tasks: {}` | `io.modelcontextprotocol/tasks: {}` | task-eligible durable submitは`CreateTaskResult` | get/update/cancelを有効化 |

serverはeffective protocolが`2026-07-28`でTasks adapterが有効な場合だけ、
`server/discover`の`capabilities.extensions`へextensionをadvertiseする。client declaration
がないrequestへ`CreateTaskResult`を返してはならない。旧`2025-11-25` experimental
Tasksはwire incompatibleなので実装せず、legacy `task` parameterをopt-inとして扱わず、
`tasks/list`と`tasks/result`も公開しない。

`tools/list`は全matrix行でbyte-equivalentである。task supportはtool metadataを増減させず、
MCP protocol resultのunionだけを変える。read-only/synchronous toolはnegotiationにかかわらず
通常の`CallToolResult`を返す。durable submit toolは、両extensionがnegotiatedなら常に
`CreateTaskResult`、それ以外なら常にbaseline `OperationAccepted`を返し、server裁量の
非決定的分岐を作らない。

### Result union and creation

task-eligible durable submitのwire resultは次のclosed unionである。

```text
CallToolResponse = Complete(CallToolResult<OperationAccepted>)
                 | Task(CreateTaskResult)
```

`CreateTaskResult`は`resultType: "task"`、`taskId: operation_id`、journalの
`created_at` / `updated_at`、mapped status、`pollIntervalMs: 1000`を持つ。serverは
journal recordとrunner handoffのcommit後、別connectionの`tasks/get`が同じIDを
解決できることを確認するまで返さない。

`ttlMs`はcreationからexecution hard deadlineとterminal retention 7日を含む期限までの
millisecond durationとする。terminal化した時点で、creationからterminal timestampと
7日を加えた値へ更新できる。recordは`tasks/get`が最後に返した最新の
`createdAt + ttlMs`より前にpurgeしない。期限後は30日のtombstoneを保持し、expired IDへの
task requestを`-32602` Invalid paramsとする。

### `tasks/get` and terminal result

`tasks/get`はjournalのread-only viewであり、同じrepository identityと`Read` capabilityを
毎回検証する。存在しない、expired、tombstoneだけのIDは`-32602`、identityまたは`Read`
不一致は`CAPABILITY_DENIED`を返し、いずれもjournalを変更しない。v1 toolsはmid-task
inputを要求しないため`input_required`へ遷移しない。`tasks/update`も同じrepository
identityと`Read` capabilityを検証し、既知かつ認可済みのIDにempty acknowledgementを
返してunknown `inputResponses`を無視する。認可失敗は`CAPABILITY_DENIED`で変更を行わない。

| Journal state / outcome | MCP task status | Payload |
| --- | --- | --- |
| `queued` / `running` / `cancelling` | `working` | result/errorなし。cancel ack後もterminalになるまで`working`でよい |
| `completed` with normal result | `completed` | originating `CallToolResult`を`result`へinlineする |
| `failed` with typed tool execution error | `completed` | `isError: true`のoriginating `CallToolResult`を`result`へinlineする |
| `failed` with JSON-RPC execution error | `failed` | closed JSON-RPC errorを`error`へinlineする |
| `cancelled` | `cancelled` | result/errorなし |

`tasks/get`のterminal payloadと`operation_result`が返すoriginating tool outputは同じ
canonical DTOから生成する。Tasks adapterがraw journal payload、absolute path、worker
stderr、credential-shaped valueを追加してはならない。

### `tasks/cancel` authorization

`tasks/cancel`はbaseline `operation_cancel`と同じmanagerを呼び、次の順序を固定する。

1. protocolと両extension declarationを検証する。server未対応は`-32601`、client未宣言は
   `-32021`で、journalへ触れない。
2. task IDを同じrepositoryのoperation recordとして解決する。unknown/expiredは
   `-32602`で、journalへ書かない。
3. current capability setがrecordに固定されたrequired capability setをすべて包含する
   ことを再検証する。不足時は`CAPABILITY_DENIED`で、journal digest、lease、runnerを
   変更しない。
4. non-terminal recordだけを`cancelling`へ進めcancel intentをrunnerへ渡す。terminal
   recordはempty success acknowledgementを返すがstatus/resultを変更しない。

acknowledgementはcancel完了を意味しない。runnerが協調できれば`cancelled`、cancelより先に
完了すれば`completed`または`failed`となる。clientは必要なら`tasks/get`またはbaseline
`operation_get`をpollする。task IDを知っていることだけでrequired capability checkを
迂回できない。

### Disconnect, restart, and reconnection

- stdio EOFとMCP server終了はoperationをcancelしない。runnerはjournal leaseとdeadlineで
  継続し、rmcp runtimeやSDK `TaskManager`のlifetimeへ所有権を置かない。
- Tasks-aware clientは`taskId`を保存し、新しいserver processで`2026-07-28`とextensionを
  再negotiationした後、同じIDを`tasks/get` / `tasks/cancel`へ渡せる。
- 再接続先がTasks非対応、extension未宣言、またはlegacy protocolでも、同じIDを
  `operation_get` / `operation_result` / `operation_cancel`へ渡して回収できる。
- submit responseを受信できなかったclientは同じidempotency keyでretryし、同じ
  `operation_id == taskId`を再取得する。別IDのworkを開始しない。
- journal integrity、repository identity、required capability digest、leaseが検証できない
  場合はfail closedとし、status/resultを推測したりoperationを自動再実行したりしない。

## Compatibility and conformance tests

後続実装はunit、protocol integration、process restart E2Eで次のmatrixを固定する。

| Test | Required assertions |
| --- | --- |
| Modern Tasks path | both extensionsでdurable submitが`CreateTaskResult`を返し、直後の`tasks/get`が同じIDを解決する |
| Non-Tasks fallback | client extensionなしで同じsubmitが`OperationAccepted`を返し、baseline get/result/cancelだけでterminal outputを回収する |
| Legacy fallback | `2025-11-25`でextension declarationを無視し、baseline result、`tasks/* = -32601`、legacy list/result非公開を確認する |
| Catalog parity | Tasksあり/なし/legacyの`tools/list` canonical bytesとtool schemaが一致する |
| Result union | complete/task discriminator、tool error=`completed + isError`、JSON-RPC error=`failed + error`をgolden wire fixtureで確認する |
| Reconnect | stdio切断とserver process再起動後、Tasks pathとbaseline pathの両方が同じID、status、terminal resultを返す |
| Idempotent retry | lost accepted response後のsame-key retryが同じrecordと`operation_id == taskId`を返す |
| Cancel authorization | allowed cancel、missing extension、unknown ID、repository mismatch、insufficient required capability、terminal no-opを検証し、denied caseでjournal digestが不変である |
| Retention | advertised TTL以前はget可能、expiry後は`-32602`、tombstone中のsame-key retryはduplicate workを作らない |
| rmcp conformance | `rmcp 3.1.0`のmodel serializationとhandler/client APIに対するofficial extension wire fixtureを通す |

## Open questions

| ID | Status | Resolution |
| --- | --- | --- |
| `Q-002` | **Resolved** | Option Aを採用する。Tasksはdurable baseline operation recordへのadditive viewであり、baseline toolsとrecovery contractを置換しない |

`open_questions`は`0`である。capability negotiation、result union、cancel認可、
再接続、legacy fallback、compatibility testに未決定の分岐は残さない。

## Issue #295 contract evidence

Issue #295の実装はQ-002 Option Aを次の型境界へ写像する。

| Design decision / acceptance area | Contract evidence |
| --- | --- |
| portable baselineを常時維持 | `OperationAccepted`はversion、`operation_id`、queued status、`operation_get` / `operation_result` / `operation_cancel`の固定recovery名を持つ |
| Tasksはadditive view | `DurableSubmitResult`はbaseline `OperationAccepted`またはnegotiated `TaskAccepted`のclosed unionであり、Tasks branchは`TaskId::from_operation_id`だけで構築する |
| `taskId == operation_id` | negotiation integration testが両branchのidentityを同一operation IDとして検証する。別task storeやmutable ID mappingはcontractにない |
| common and closed wire DTO | common request、snapshot selector、success/error envelope、page/cursor、Agent node/site/edge/evidence/snapshotのSerde deserializationとschemaがunknown fieldを拒否する |
| bounded, portable disclosure | Agent DTOはsummary fieldだけを持ち、arbitrary metadata/properties、raw evidence detail、absolute root/store pathを受理しない。repository path scalarはportable relative pathだけを受理する |
| typed failures and pagination | error codeからcategoryを導出し、wire上のcategory偽装を拒否する。page item/byte bounds、returned count、total count、complete/cursor関係をconstructorとdeserializerで検証する |
| deterministic schema artifact | `generate-schema`はcanonical JSONを末尾改行なしで出力し、`schemas/depgraph-mcp-tools-v1.schema.json`とのbyte equality、再実行間のbytes/SHA-256、全objectの`additionalProperties: false`をintegration testで固定する |
| golden evidence | `crates/depgraph-mcp-tools/tests/fixtures`のcanonical contract sampleとschema digestをexact comparisonする |

このevidenceはIssue #295のcontract/schema scopeだけを証明する。Q-002で定義した
protocol negotiation、journal durability、disconnect/restart recovery、Tasks handlerの
conformanceは、上記[Compatibility and conformance tests](#compatibility-and-conformance-tests)
に従う後続実装の責務である。

## Issue #301 lifecycle tool evidence

Issue [#301](https://github.com/TamaT-LLC/depgraph-cli/issues/301)はread-only lifecycle
操作をCLI固有実装から共有service boundaryへ移し、同じdomain resultをMCPへ公開する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Shared requests | `ProfilePlanRequest`と`DoctorRequest`はtyped fieldだけを持つ。profile budget、inline document、repository fileの競合をfail closedにし、daemon statusにはrequest payloadを持たせない |
| Profile input confinement | inline documentはUTF-8 byte limit内、fileはportable `RepositoryRelativePath`だけを受理する。handle-relative/no-follow openでparent/final symlink、traversal、absolute/outside path、non-regular file、oversized/non-UTF-8 inputを拒否する |
| Profile execution | profile planningはconfigとstatic repository inventoryだけを読み、worker discovery/probe、compiler、project command、store openを行わない。build script markerとmissing-store immutability testで検証する |
| Daemon observation | store pathから固定status filenameを導出し、そのregular fileをno-followで一度だけbounded readする。store、daemon lock、stop request、PID/process probeには触れない |
| Doctor projection | core `DoctorResponse`はallowlist fieldだけをserializeする。worker command/error/log、adapter log、profile environment/properties、diagnostic message/properties、release runtime path/requirement、diagnostic root pathを除外し、残る自由文字列もlength/control/path/credential shapeでsanitizeする |
| Frontend parity | CLIの`profiles plan`、`daemon status`、`doctor`とMCPの`profile_plan_get`、`daemon_get`、`doctor_get`は同じservice methodを呼び、JSON公開時は同じ`AgentProfilePlan`、`AgentDaemonStatus`、`AgentDoctor` projectionを使う |
| Runtime controls | MCPの三handlerはread classのadmission、rate、queue/concurrency、30秒deadlineとrequest cancellationを維持する。serviceもI/O、probe、projectionの境界で同じcancellation tokenを検査する |
| Closed deterministic contract | 三toolはgeneric JSON resultを使わず固有Agent DTOのexact output schemaをadvertiseする。全objectは`additionalProperties: false`であり、catalog bytes/digest、global schema bytes/digest、contract samplesをrepository-native golden commandで固定する |
| Regression proof | core service、CLI process、MCP stdio process、advertised/shared schema、store/status digest immutability、redaction prohibition corpus、CLI/MCP value parityをintegration testで検証する |

profile fileのlegacy CLI absolute pathはrepository内部を指す場合だけportable relative pathへ
normalizeして互換性を維持する。repository外、`..`、symlinkを含む場合はsecurity failureとし、
supplied pathやcontentをerrorへ反射しない。daemon/doctorのhuman outputはCLI向け表示を維持できるが、
JSON domain responseはAgent projectionをcanonical sourceとする。

## Issue #302 dependency/path tool evidence

Issue [#302](https://github.com/TamaT-LLC/depgraph-cli/issues/302)は既存の`deps`、
`dependents`、`why` graph semanticsを共有service境界へ移し、三つのread-only MCP toolへ
公開する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Snapshot ownership | handler/CLIはlocatorまたはlegacy scan selectionをrequest-owned read-only storeで一度だけstable snapshot IDへ解決する。graph loadは同じ`SnapshotReadRequest`と固定IDを使い、後続scanがcurrent pointerを変えても開始時snapshotだけを読む |
| Dependency traversal | `DependencyDirection::{Outgoing,Incoming}`、one-hop/transitive、normalized `GraphQueryFilter`を共有する。adjacencyはnext node ID、edge ID、public resultはedge IDでcanonical orderを固定し、bounded traversalはpartialであることを`traversal_complete`へ明示する |
| Pagination | dependency cursorはcontract、tool、repository、resolved snapshot ID、direction、selector、transitive、filter、traversal limit、およびcanonical collection digestへ暗号学的にbindする。別snapshot/query/toolのcursorは`CURSOR_MISMATCH`となる |
| Path search | canonical adjacency上のBFSで単一shortest pathを選ぶ。同一nodeはzero-step found path、完全探索したunreachableだけはempty stepsと`path_found: false`、未探索edgeを残すlimit到達は`DepgraphServiceError::ResourceExhausted`となる |
| Closed Agent mapping | `AgentDependenciesResponse`、`AgentPathResponse`、`AgentPathStep`は`deny_unknown_fields`、`JsonSchema`、validated constructorを持つ。edgeは既存`AgentEdge`、evidenceはcanonical先頭64件の`AgentEvidence`だけを使い、raw detail/properties、absolute evidence path、private node propertyを公開しない |
| Runtime controls | 三handlerは`RuntimeController` read class、fixed `Read` authorization、request cancellation、deadline、rate/concurrency/queue limitsを通り、service traversalもcooperative cancellationを検査する |
| Frontend parity | CLIのlegacy full JSON/human形とpaged JSON contractを維持したまま、graph executionだけを共有serviceへroutingする。MCP process testは同じstore/filterから得るcanonical edge/path ID sequenceの一致を検証する |
| Deterministic artifacts | 三toolの固有input/output schema、global schema、catalog JSONとSHA-256 digestをchecked-in fixtureとして固定し、real stdio resultsをadvertised/shared schemaの双方で検証する |

### Issue #302 acceptance mapping

| Acceptance criterion | Evidence |
| --- | --- |
| direction/transitiveが既存CLI semanticsと一致する | core service matrix、既存CLI graph regression、CLI/MCP process parity |
| 同じsnapshot/filterから同じpath/order/cursorを返す | canonical-order service test、repeated/cursor process test、cursor fingerprint binding |
| traversal上限をpathなしと誤認しない | service exhaustion testとstdio `RESOURCE_EXHAUSTED` test |
| concurrent scan中も開始時snapshotだけを参照する | currentを解決後に別snapshotをpublishするrequest-pinning service test |
| closed schemaとredaction | DTO constructor/Serde/schema tests、およびprivate path/property prohibition process corpus |
| repository validation | focused tests、workspace formatting、Clippy `-D warnings`、`cargo xtask test` |

## Issue #303 impact/cycle/unresolved tool evidence

Issue [#303](https://github.com/TamaT-LLC/depgraph-cli/issues/303)は既存の`impact`、
`cycles`、`unresolved`を共有read-only serviceへ移し、同じcanonical resultを三つの
MCP toolへ公開する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Snapshot and changed set | selector-only requestは任意のcompleted snapshotを使える。`changed_since`はlocatorが厳密に`current`のrequestだけを許し、Gitが返すHEADとsnapshotの`source_revision`が一致しなければpartial resultを作らず`SNAPSHOT_WORKTREE_MISMATCH`を返す |
| Cache independence | `DepgraphService::impact`はrequest-owned read-only storeから固定snapshotを読み、毎回canonical mapping、adjacency、shortest path、reverse traversalを計算する。impact query cacheのlookup、insert、touch、event記録を行わず、CLI/MCP反復testはstore digestとcache entry countの不変を検証する |
| Canonical impact | selector、optional Git changed set、normalized depth/profile/condition/phase/session/environment filterを一つの`ImpactRequest`へ集約する。changed path/node mappingとdependency pathはstable ID順、canonical adjacency/BFS順で固定し、上限到達時は`complete: false`を公開せず`RESOURCE_EXHAUSTED`へ変換する |
| Bounded cycles | `CyclesRequest`はclosed `CycleLevel`とtraversal limitだけを持つ。node/edge preprocessing、iterative SCC traversal、representative cycle search、sort/finalizationは独立budgetとcancellation checkを持ち、`AgentCycleLevel`および先頭末尾が同じbounded `AgentCycle`だけを公開する |
| Bounded unresolved projection | `UnresolvedRequest`はnormalized kind filterとtraversal limitを持つ。evidence/edge/correlation preprocessing、site traversal、projection/finalizationをbudget/cancellation境界にし、一siteあたりevidence 64件、target 256件、correlation reason 16件を超える入力は全resultを破棄する |
| Closed disclosure | `AgentImpactResponse`、`AgentImpact`、`AgentCycle`、`AgentUnresolved`、拡張`AgentSite`はunknown fieldを拒否する。unresolved evidenceはkind/extractor/versionとportable relative spanだけ、profile/correlationはclosed ID/enumだけを返し、raw detail/properties、environment、absolute path、secret-like private dataを投影しない |
| Pagination and runtime | 各cursorはcontract、tool、repository、resolved snapshot ID、normalized selector/changed-set/filter/level/kind/budget、およびcollection digestへbindする。handlerはread admission、deadline、rate/concurrency/queue limitとrequest cancellationを維持し、service/Git child pollingもcooperative cancellationに従う |
| Frontend parity and artifacts | CLI三commandとMCP三handlerは同じservice methodを呼ぶ。real stdio/CLI process testがimpact node、cycle path、unresolved site IDを比較し、successをadvertised exact schemaとchecked-in shared schemaの双方で検証する。catalog/schema/contract JSONとdigestはrepository-native golden更新commandで固定する |

### Issue #303 acceptance mapping

| Acceptance criterion | Evidence |
| --- | --- |
| `changed_since`はcurrent snapshotだけ、HEAD不一致はtyped failure | named-snapshot rejection、dirty-worktree success、commit後のreal-process `SNAPSHOT_WORKTREE_MISMATCH` test |
| impactはread-onlyでcache非依存 | service/CLI反復canonical equality、impact cache count zero、MCP store digest/row/current pointer immutability |
| cycle/unresolved outputはclosed、bounded、redacted | DTO constructor/Serde/schema enum・topology・length testとhostile evidence process corpus |
| 全phaseがbounded/cancellableでpartial successなし | core cancellation/resource tests、wide preflight、stdio三toolの`RESOURCE_EXHAUSTED`かつresultなしtest |
| cursorはsnapshotとnormalized inputへbindする | repeated first-page equalityとfilter変更時`CURSOR_MISMATCH` process test |
| CLI/MCP/domain/schema/catalog parity | shared-service integration、cross-process ID parity、real output advertised/shared validation、canonical catalog/schema/contract golden |
| repository validation | `cargo fmt`、影響packageのfocused unit/integration/process tests、`git diff --check`。workspace-wide expensive gateはparent validationに委譲する |

## Issue #304 bounded query/runtime validation evidence

Issue [#304](https://github.com/TamaT-LLC/depgraph-cli/issues/304)は既存のbounded queryと
runtime trace validationをCLI固有のstore orchestrationから共有read-only serviceへ移し、
同じ境界を二つのMCP toolへ公開する。過去のtask記述にあるFR/AC番号は本書の追加要件で
再配置されているため、現在の`FR-004`、`NFR-001/003/005`、`AC-009/010/015`へ対応付ける。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Exactly-one input | service requestとpublic tool schemaの双方がinlineまたはfileの一方だけを受理する。CLIのclap制約だけには依存せず、none/bothを`INVALID_ARGUMENT`で拒否する |
| Query prevalidation | query size、stable confined file read、parse、credential-shape policy、closed type check、およびservice/planner output ceiling admissionをstore/snapshot requestより前に完了する。不正入力とoutput cap超過はmissing storeを作成せず、後者は`QUERY_REJECTED`となる |
| Confined file input | `RepositoryRelativePath`とhandle-relative/no-follow readerを使い、absolute、`.`/`..` escape、parent/final symlink、non-regular、oversized、read中にidentity/size/mtimeが変化したfileをfail closedに拒否する。errorはraw query/trace/supplied pathを反射しない |
| Pinned read-only execution | query plan/executeとruntime matchingは一度解決した`SnapshotReadRequest`のimmutable completed snapshotだけを読む。writer store、cache、attempt、snapshot/current pointer、runtime import、source treeを変更しない |
| Bounded query execution | plannerのsnapshot cardinalityとclosed field byte boundsからworst-case rows/serialized bytes/work/memoryを計算し、execution前に全capを判定する。execute modeの非admit planはpartial rowを返さず`QUERY_REJECTED`、explain modeは同じredacted planを返す |
| Runtime validation | bounded trace JSONをcredential/shape validationしてからrepository identity/revision、profile、locatorをselected snapshotへmatchする。promotion用deltaやruntime sessionを書かず、closed summaryとpaged event projectionだけを返す |
| Closed Agent DTO | query scalar/node/pathは`AgentQueryValue`のtagged unionへ縮約し、node/pathのraw properties、site/evidence detailを公開しない。runtime outputはschema/profile status、summary、event ID/kind/count、resolved node IDだけを持ち、raw repository/session/environment/redaction name/pathを除外する。constructor/Deserializerはpath topology、match status、summary/page countを再検証する |
| Pagination/runtime control | cursorはcontract、tool、repository、resolved snapshot ID、canonical query/trace digest、collection digestへbindする。両handlerは`RuntimeController`のRead admission、deadline、rate/concurrency/queue limit、request cancellation内で同期実行する |
| Determinism and parity | inline/file、repeated first page、cursor mismatch、CLI/MCP query valuesとruntime summary/event IDをreal process testで比較する。advertised exact schemaとchecked-in shared schema、catalog/schema/contract goldensを同じsuccessへ適用する |

### Issue #304 acceptance mapping

| Acceptance criterion | Evidence |
| --- | --- |
| invalid/credential queryはstore前に非反射で拒否 | core missing-store testsとMCP hostile process corpus |
| worst-case output cap超過はexecution前の`QUERY_REJECTED` | configured service-limit test、hostile planner process test、typed error mapper test |
| runtime validateは永続状態を変更しない | store digest/row/current pointer、snapshot ID、source-file digestのservice/CLI/MCP tests |
| inlineまたはroot-confined regular fileだけを受理 | service exactly-one、absolute/traversal/symlink/nonregular/oversize testsとcatalog `oneOf` validation |
| closed/paged/cancellable Agent response | DTO semantic Deserialize、schema closure、input-bound cursor、Read runtime controller process tests |
| CLI/MCP/catalog/schema parity | shared-service routing、real stdio parity/security test、canonical schema/catalog/contract fixtures |
| repository validation | focused core/CLI/MCP tests、`cargo fmt`、Clippy `-D warnings`、`cargo xtask test` |

## Issue #305 snapshot artifact evidence

Issue [#305](https://github.com/TamaT-LLC/depgraph-cli/issues/305)はsnapshot diff、policy
evaluation、output先を持たないinline graph exportをCLI固有のorchestrationから共有serviceへ
移し、同じ境界を三つのMCP toolへ公開する。file outputは既存のrepository-confined CLI
workflowを維持し、inline MCP responseだけにhard byte boundと`export_file` remediationを適用する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Snapshot pinning | `current`、named、ID selectorはrequest開始時にcompleted snapshot IDへ一度だけ解決し、diff/policyのfrom/toとexport対象を処理完了まで固定する |
| Shared canonical artifacts | CLIとMCPは同じ`DepgraphService`のdiff、policy、graph export methodを呼ぶ。completed snapshotのoutputなしCLI exportもAgent-safe canonical projectionをそのまま出力し、raw互換projectionは`--output`または明示したfailed/partial scanだけに限定する。handlerはrequest変換とclosed DTO projectionだけを担当し、diff/policy/export logicを複製しない |
| Policy identity | policy resultはrules、suppressions、selector exclusions/scopes、profile filters、precision/status/evidence sets、commutative condition operandsを意味的なsetとして正規化したconfigurationのSHA-256 digestだけを公開する。source配列順は評価にもidentityにも影響せず、raw config、arbitrary graph properties、host path、credential-shaped dataはAgent DTOへ投影しない |
| Inline export bounds | JSON、DOT、Mermaid、GraphMLをnode、edge、canonical wire byte ceiling内で全体生成する。上限超過時はpartial contentを捨て、`RESOURCE_EXHAUSTED`と`export_file` remediationを返す。final envelope serialization超過にも同じremediationを維持する |
| Closed contracts | `AgentSnapshotDiffResponse`、`AgentPolicyEvaluationResponse`、`AgentGraphExportResponse`とnested DTOはunknown fieldを拒否し、advertised exact output schemaとchecked-in shared `$defs`の双方へ登録する |
| Runtime and confidentiality | input validationとrepository confinementをstore access前に行い、全service phaseはcooperative cancellationをpollする。service errorはraw locator/config/contentを反射せずtyped errorへ変換する |

### Issue #305 acceptance mapping

| Acceptance criterion | Evidence |
| --- | --- |
| selectorをrequest開始時にcompleted IDへ固定 | shared service pinning testsとresolved IDを含むclosed result |
| CLI/MCPが同じcanonical diff/policy/exportを返す | shared-service routing、focused core tests、real process content/digest parityとraw property omission test |
| policy identityはraw configでなくcanonical digest | source配列順を逆転したrules、suppressions、nested set/conditionのdigest/result identity regressionとclosed DTO/schema prohibition |
| inline exportはboundedでpartial responseなし | four-format deterministic tests、node/edge/byte exhaustion tests、post-serialization `export_file` mapper regression |
| MCP contract/schema/catalogがexactかつclosed | catalog golden、shared schema/digest golden、unknown-field rejectionとresponse definition tests |
| repository validation | focused core/CLI/MCP tests、`cargo fmt`、Clippy `-D warnings`、`cargo xtask test` |

## Issue #310 portable operation recovery evidence

Issue [#310](https://github.com/TamaT-LLC/depgraph-cli/issues/310)はportable baselineの
三toolをproduction MCP handlerからrepository-bound operation managerへ接続する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Closed status projection | `AgentOperation`はoperation ID、closed status、bounded progress、timestamps、retentionだけを公開する。constructorとDeserializerはprogress、terminal status/timestamp、deadline順序を検証し、journal input、kind、capability digest、lease、runner handoffを型に持たない |
| Exact contract artifacts | `operation_get`、`operation_result`、`operation_cancel`はgeneric `result: true`を使わず、closed success/error envelopeだけをadvertiseする。catalog、shared schema、contract sampleとSHA-256 fixtureをexact comparisonで固定する |
| Repository and capability authority | handlerはrequest repository identityをmanager open前に検証する。status/resultは毎回sealed repositoryと`Read`を検証し、cancelはrecordへ固定された全required capabilityの包含を再検証する。read-only denialとterminal no-opではlogical journal stateが不変である |
| Terminal result boundary | terminal payloadはregistered closed success envelopeまたはtyped error envelopeへdeserializeし、repository、operation ID、terminal stateとの一致を再検証してからsole canonical response mapperへ渡す。unknown shape、identity mismatch、raw journal payloadは`INTEGRITY_FAILURE`となり公開されない |
| Fail-closed error mapping | 全`JournalError` variantをexhaustive matchでtyped Agent errorへ変換する。SQLite/I/O source text、journal payload、path、lease情報をerrorへ反射しない |
| Restart and idempotency | process E2Eはqueued/running/not-ready、stdio EOF、別server processからのterminal status/result回収、same-key manager retryによる同一ID回収、denied/allowed cancel、terminal no-opを同じSQLite journalで検証する |

## Issue #312 scan / snapshot store-write evidence

Issue [#312](https://github.com/TamaT-LLC/depgraph-cli/issues/312)はCLI固有だったsafe scanとcompleted snapshot namingを共有`DepgraphService`のstore-write境界へ移し、`scan_submit`をdurable operation runnerへ接続する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Shared store-write service | CLI、portable operation runner、MCP snapshot namingは同じ`DepgraphService` use caseを呼ぶ。serviceは`Read + StoreWrite` capability、canonical repository root、store writer lock、cooperative cancellationを一度だけ適用し、frontendへstore internalsを公開しない |
| Safe scan semantics | scanはcancellation-aware safe pathだけを実行し、`project_code_executed: false`をclosed terminal resultへ固定する。cancelled、failed、partial scanはcompleted/current snapshotを置換せず、source tree digestも変更しない |
| Durable handoff | `scan_submit`はbounded canonical inputとidempotency keyをoperation journalへcommitし、fresh observerからhandoff visibilityを確認してdetached runnerを起動する。request cancellationがrunner launchより先にlinearizeした場合はunclaimed handoffを同じjournalでterminal `cancelled`にしてlaunchを抑止する。launchが先またはtransportが切断済みの場合にresponse deliveryは保証せず、same-key retryで同じoperationを回収する |
| Cancellation precedence | operation scanはvalidation後もstore writer lockを保持し、current promotionをdeferする。runnerは最終poll後、journalのIMMEDIATE transactionでcancel/deadline/leaseと成功completion intentを直列化し、cancelが先ならscanをnon-promoted `cancelled`へ、completion intentが先なら後続cancelをno-opにしてからcurrentをpromoteする。したがってpoll追加だけに依存せず、cancelled/failed/partial operationはcurrentを置換しない |
| Completion crash recovery | completion intentはclosed terminal payloadをjournalへ先にdurable化するがpublic statusを増やさない。runnerがintent commitとstore promotionの間、またはpromotionとjournal terminalizationの間で停止しても、再起動runnerはdeadline purgeと次work claimより先にintentを読み、staging scanのsnapshot identityを再検証してpromotionをidempotentに完了し、同じpayloadでjournalを`completed`へ進める |
| Closed scan result | `AgentScanOutcome`はcompleted status、scan ID、`project_code_executed`、bounded coverage、closed cache summary（hit/miss件数）だけを公開する。cache key、reason、worker log、journal payloadは投影せず、cold/warm process testでmiss/hitを検証する |
| Immutable completed naming | `snapshot_name_create`はcurrent、stable snapshot ID、またはcompleted scan selectionだけを受理し、completed snapshotへimmutable nameを一度だけ作成する。failed/partial attemptとduplicate/case-folded duplicateはtyped failureになりcurrent pointerを変更しない |
| Capability and contract gating | `scan_submit`と`snapshot_name_create`はstore-write capabilityなしの`tools/list`へ現れず、直接callもfail closedに拒否する。exact advertised schema、shared schema、catalog/contract JSONとdigest fixtureをcanonical generatorで固定する |

### Issue #312 acceptance mapping

| Acceptance criterion | Evidence |
| --- | --- |
| journal commitとrunner handoff後2秒以内にhandleを返す | MCP process testのelapsed bound、fresh-manager visibility、stdio EOF後のreconnect polling |
| safe scanはproject codeを実行せずsource treeを変更しない | core service test、durable runner terminal DTO assertion、scan前後source digest equality |
| cancelled/failed/partialはcurrent completed snapshotを置換しない | core cancellation regression、runner cancel-vs-complete race test、existing scan promotion regressions |
| terminal resultからcoverageとcache hit/missを取得できる | closed DTO/Serde/schema tests、cold miss→warm hitのMCP process test |
| namingはcompleted-only、immutable、writer serialized | service missing/partial/duplicate/lock testsとMCP duplicate-name process test |
| store-write capabilityなしではdiscover/call不可 | catalog capability filterとread-only MCP process test |
| repository validation | Rust 1.93.1 format、workspace Clippy `-D warnings`、focused suites、`cargo xtask test` |

## Issue #313 runtime import store-write evidence

Issue [#313](https://github.com/TamaT-LLC/depgraph-cli/issues/313)は既存のruntime trace validation、snapshot matching、runtime session delta生成、store unionを共有`DepgraphService`のstore-write use caseへまとめ、`runtime_trace_import_submit`をdurable operation runnerへ接続する。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Pre-journal validation | inline `trace`またはrepository-relative `trace_file`のexactly-oneだけを受理する。既存`runtime_trace_validate`と同じbyte/event/string/nesting/credential/parse制約、handle-relative no-follow regular-file read、confinement、stable identity checkをmutation-free source prevalidationとしてoperation journal openより先に完了する。raw traceがvalidになって初めてexisting idempotency bindingを参照し、default/current replayをoriginal immutable snapshotへpinしてsnapshot matchingと`RuntimeSessionDelta`生成を行う。したがって旧journalが存在してもinvalid traceによるschema migrationは起きない |
| Durable input identity | journalはinline traceのcanonical parsed value、またはconfined file locatorを保持し、いずれもvalidated trace digestと開始時に解決したimmutable base snapshot IDへbindする。operation inputの16 MiB上限は、1 MiB raw inline上限 + 100,000 eventそれぞれのdefault/timestamp正規化増分128 bytes + session固定増分512 bytes + binding envelope 1 KiBという保守的なclosed bound（13,850,112 bytes）を包含する。`trace_file`はjournal参照後にも再度stable readしてprevalidation時のexact normalized valueと一致させ、runnerも同じ境界で再読し、digestまたはsnapshot identityのdriftをstore mutation前にfail closedとする |
| Shared promotion | CLI、runner、restart recoveryは同じ`DepgraphService` runtime import methodを呼ぶ。serviceだけが`Read + StoreWrite`、store writer lock、base snapshot integrity、runtime delta union、`Store::import_runtime_session`またはdeferred staging/finalizationを所有する |
| Cancellation linearization | runnerはvalidated runtime deltaをstagingに保持したままcurrent promotionをdeferする。store schema v16の`runtime_import_operation_owners(import_id, operation_id)`をstaging transaction（deterministic replay/dedupを含む）でdurable化する。cancel/deadline cleanupは当該operation ownerだけを同一store transactionでreleaseし、ownerがゼロになったstaging import/sessionだけを削除する。completed import/snapshotは削除せず、owner evidenceのないv15以前のstagingはfail-safeに保持する |
| Crash recovery | completion intentはclosed terminal payloadを先にdurable化する。intent commit後のrunner停止は次runnerがwork claimより先にruntime import/session/prospective snapshot identityを再検証し、staging promotionまたは既に完了したpromotionをidempotentにfinalizeする。promotion transactionは全owner referenceを消去するためcompleted importにstale ownershipを残さない。別idempotency keyが同じdeterministic stageを共有していても、一方のcleanupはcommitted intentを持つ他方のrecovery evidenceを破棄できない |
| Closed parity result | `AgentRuntimeOutcome`はruntime import ID、runtime session ID、completed snapshot ID、closed `completed` / `partial` status、deduplication flagだけを持つ。CLI JSON domain resultとMCP terminal success envelopeは同じservice outcomeからこのDTOを構築し、envelope snapshot IDとの一致をterminal contractで再検証する |
| Capability and artifacts | `runtime_trace_import_submit`はstore-write profileだけにdiscover/call可能で、idempotency key、exactly-one trace input、optional completed snapshot selectorだけをadvertiseする。catalog、shared schema、terminal result unionとdigest fixtureはcanonical generatorで固定する |

### Issue #313 acceptance mapping

| Acceptance criterion | Evidence |
| --- | --- |
| invalid traceはjournal/store mutation前にtyped failure | missing-store service test、inline/file credential-shaped MCP process test、既存v2 journalのbyte/row/schema/user_versionとstore invariant不変 assertion |
| valid traceだけが新しいimmutable completed snapshotへatomic union | immediate/deferred service tests、runtime store transaction tests、MCP terminal/current snapshot process assertion |
| cancel/failureはpartial/currentを公開しない | deferred service cancellation、runner completion-window cancellation、malformed/digest drift failure test、二operation共有stageのowner barrier/recovery test |
| CLIとMCP terminal outcome parity | shared `AgentRuntimeOutcome` conversion、CLI runtime import regression、MCP terminal closed-contract test |
| idempotencyとrestart recovery | same-key same-operation process assertion、completion-intent promotion recovery unit/integration test |
| repository validation | Rust 1.93.1 format、focused core/store/operation/CLI/MCP suites、workspace Clippy `-D warnings`、`cargo xtask test` |

## Issue #314 repository-write evidence

Issue [#314](https://github.com/TamaT-LLC/depgraph-cli/issues/314)はfixed repository rootの
初期化とrepository-relative graph file exportを共有`DepgraphService`へ移し、
`repository_init`をimmediate tool、`export_file`を常時durable operationとして公開する。
Issue本文に残る旧`FR-005/008/009/010/011`、`NFR-008`、`AC-013`参照は現在の
[Requirement traceability](#requirement-traceability)表と一致しない。本実装は現在存在する
`FR-010`（durable handle）、`NFR-001`（bounds/cancel）、`NFR-003`（restart recovery）、
`NFR-005`（host-private情報の非公開）、`AC-014`（baseline/Tasks recovery）、
`AC-015`（CLI/MCP shared-service parity）および`#314`行へ対応付ける。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Fixed-root init | public requestは`force`だけを持ち、root/path selectorを持たない。serviceはsealed root直下の固定`.depgraph.toml`だけをsame-directory stageへ書き、content sync後にno-replaceまたはregular-file overwriteでatomic publicationする。symlink、Windows reparse point、directory等のnon-regular targetは`force`でも置換しない |
| Portable confinement | `RepositoryRelativePath`はabsolute、empty、`.`/`..`、backslash/prefix、NTFS stream、Win32 trailing alias、reserved device、component/total byte超過を拒否する。Unixはretained directory FD + `openat`/`fstatat`/`linkat`/`renameat`、Windowsはretained directory handle + `NtCreateFile`/`SetFileInformationByHandle`を使い、全parent/final componentをno-followで検証する。root identity driftはpublication前にfail closedとなる。graph store parentがconfig時に存在する場合はそのobject identityをsealし、generic createとatomic publicationの実parent handle identity + Unicode/case-equivalent protected leaf名を照合するため、lexical validation後のdirectory renameでもstore・journal・SQLite sidecar・runner purge lockへ書けない。repository内parentがconfig時に未作成ならprotected leaf namespaceをfail closedで予約する |
| Atomic export | contentはdestinationと同じdirectoryのprivate stageへ全体生成し、file sync後にexplicit no-replace/overwrite policyでatomic publishする。Unixはopened random-stage inodeとpathname entryをpublication直前・直後に照合し、foreign replacementを成功として採用しない。foreign entryは削除せず、overwrite exchange後に検出した場合はoriginal destinationをidentity-bound exchange-backする。cleanupも検証済みの元stage pathnameを直接unlinkせず、128-bit random quarantine名へatomic no-replace moveしてからidentityを再判定し、foreign swapは元名へ戻すかquarantineに保持する。parent directoryもsyncし、writer/cancel/publication failureはowned random stageだけを除去して既存destinationを維持する。CLIのcompleted raw-compatible outputとfailed/partial legacy projectionもpublicationだけは同じservice境界を通る |
| Durable ownership | `export_file` normalized inputは開始時のstable snapshot ID、format/filter/bounds、portable output path、overwrite policy、private destination preconditionをcanonical/bounded journal inputへ固定する。stage名はoperation IDとoutput pathから決定的に導出するがpublic resultへ出さず、`.depgraph-export-<64 lowercase hex>` namespaceとそのcase aliasは全public repository outputで予約する。同じoperationのexact stageだけをlength/SHA-256一致でadopt/removeし、foreign stageは保持してintegrity failureとする |
| Completion and recovery | runnerはstage完成後にもcancel/deadline/leaseをpollし、成功decisionをcompletion intentへ先にcommitしてからpublishする。decision前のcancel/expiry cleanupはowned exact stageだけを消す。decision後のrestartはexact stageまたは既にpublished済みのexact digestを認識する。成功decision後のpublication/precondition failureはsuccessをfailureへ書き換えたりowned stageを捨てたりせず、intentとstageをretryableに保持してordered runnerをfail closedで停止する。destinationを元のpreconditionへ修復した後だけ同じintentを再試行できる。recovery/cancelを含む全lifecycle entry pointはshortcutより前にgraph store・operation journal・SQLite sidecar・runner purge lockとaliasを再拒否し、recovery evidenceのzero byte・oversize・non-canonical digestをpublish前に拒否する。overwrite recoveryは開始時のregular-file identity/length/content digestが一致する場合だけfinalizeし、外部変更されたdestinationを保持してfail closedにする |
| Closed terminal result | `AgentExportOutcome`はrepository-relative `output_path`、closed `format`、positive `output_bytes`、lowercase SHA-256だけを持つ。constructor/Deserializer/schemaは全fieldを再検証し、absolute/temp path、raw graph、host metadata、arbitrary property、unknown fieldを受理しない。portable terminal success unionへclosed branchとして登録する |
| MCP and capabilities | `repository_init`と`export_file`は`Read + RepositoryWrite` profileだけにdiscover/call可能である。init handlerは共有serviceを直接呼ぶ。export handlerはdynamic `current`を初回だけstable IDへ解決し、same-key replayではjournalのoriginal bindingを再利用する。explicit stable IDとnamed selectorのconflict recoveryはrequested selectorが今回解決したstable snapshot IDとwinner bindingのIDを完全一致させ、異なるsnapshotへ同じkeyを再利用した場合はmutation-free `IDEMPOTENCY_CONFLICT`とする。`current`だけはconcurrent winnerのstable snapshot bindingを採用できるが、destination preconditionを含む他のnormalized inputはexact match必須である。baseline operation handleとnegotiated MCP Tasksは同じoperation ID/journal/runnerを使う |
| Deterministic artifacts | exact catalog、shared JSON Schema、terminal contract sampleとSHA-256 fixtureはcanonical generatorで更新する。shared schema rootはfixed-path `AgentRepositoryInitOutcome`とそのclosed success envelopeも公開する。real stdio process testはtools/list、immediate init、durable export、digest/bytes、reconnect/current replay、capability filteringを実server/runner processで検証する |

### Issue #314 acceptance mapping

| Current acceptance area | Evidence |
| --- | --- |
| fixed root以外をinitできず、forceもsymlink/reparse/non-regularを置換しない | core fixed-path/conflict/symlink/nonregular tests、Windows reparse/no-follow tests、repository_init stdio process testとcatalog input closure |
| export pathはrepository-relativeかつno-follow | path scalar rejection corpus、Unix parent/final symlink tests、root identity race tests、Windows handle-relative compile/runtime tests、CLI outside-root tests |
| no-replace/overwriteともpartialを公開しない | writer/publication failure injection、destination canary、same-directory artifact count、file/parent syncを検証するcore tests |
| cancel/deadline/lease/crashはowned stageだけを処理する | deferred cancellation、foreign/exact deterministic stage、expired operation cleanup、completion-intent restart、destination-precondition recovery tests |
| same-key replayとconflictがmutation-free | `current` advance後もdestination preconditionがexactなreplayだけ同じtask ID、`current`でdestination preconditionが異なる場合とnamed selector A/Bが異なるstable snapshotへ解決された場合はtyped conflict、changed normalized inputでtyped conflict、journal/source/destination invariant process assertions |
| terminal outputがclosedでdigest/bytesと一致する | `AgentExportOutcome` constructor/Serde/schema tests、portable result union、real exported bytesのSHA-256/length process assertion |
| capability/catalog/schema/CLI/MCP parity | repository-write catalog filter、no-root init schema、shared-service CLI security/parity、real stdio handlers、catalog/schema/contract checked-in golden exact tests |
| repository validation | Rust 1.93.1 focused core/operation/CLI/MCP tests、Windows cross-check、`cargo fmt`、affected Clippy `-D warnings`。authoritative full gateはparent validationで実行する |

## Issue #315 daemon-control evidence

Issue [#315](https://github.com/TamaT-LLC/depgraph-cli/issues/315)はdaemon start/stop orchestrationを
共有`DepgraphService`へ移し、`daemon_start_submit`と`daemon_stop`をdurable operationとして公開する。
Issue本文に残る旧`FR-005/008/009/010`、`NFR-008`、`AC-003/013/014/018`参照は現在の
[Requirement traceability](#requirement-traceability)表と一致しない。本実装は現在存在する
`FR-009`（status境界）、`FR-010`（durable handle）、`NFR-001`（bounds/cancel）、
`NFR-003`（restart recovery）、`NFR-005`（host-private情報の非公開）、
`AC-011`（status-file-only read）、`AC-014`（baseline/Tasks recovery）、
`AC-015`（CLI/MCP shared-service parity）および`#315`行へ対応付ける。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Shared lifecycle service | CLI、runner、MCPは`DepgraphService`のforeground start、running-state verification、generation-bound stop request、cleanup waitを共有する。startは二つのlifecycle lock取得後のrunning status publicationを境界とする。stop requestは専用writer lock取得後にstatusを再読し、canonical rootと`started_at`が一致するdaemon generationだけを対象にatomic publishする。daemonも同じgenerationのrequestだけを消費し、start/finalization cleanupはwriter lock下で自generationとの一致を検査する。stopはstopped status、対応するstop-control removal、lock releaseがすべて一致した後だけ成功し、既にstoppedかつcleanup済みの場合だけidempotent successである |
| Verified process launch | runnerはcurrent executableから固定されたsibling `depgraph`だけをcanonicalizeして受理し、regular executable identityを保持する。shell、PATH lookup、repository-local executable、arbitrary argument/environmentは使わず、stdioを閉じた新process groupとして起動する。running publication前のexit・deadline・contradictory statusはchild process treeをterminate/reapして失敗する |
| Durable completion and recovery | start/stopのclosed terminal decisionをcompletion intentへ先にcommitし、startはverified childのrunning publication、stopはcleanup完了をpromotion boundaryとする。runner restartは同じnormalized inputとclosed outcomeを再検証してpromotionを再実行する。decision前のcancel/deadlineはside effect前に停止し、decision後はcommitted decisionをretryableに保持する |
| Capability closure | daemon toolsとoperation kindは`Read + StoreWrite + DaemonControl`を要求する。`DaemonControl`だけ、または`StoreWrite`だけのserver設定は起動時に拒否し、catalog、submit、runner handoff、retry、cancelの各境界で同じrequired-capability digestを再認可する |
| Closed result | `AgentDaemonControlOutcome`は`action`と`phase`だけを持つclosed unionであり、PID、absolute executable/root、status/control/lock path、command、environmentを含まない。constructor、Deserializer、shared schema、portable terminal contractがunknown fieldとaction/phase不整合を拒否する |
| Deterministic evidence | exact catalog、shared JSON Schema、portable terminal contract sampleとdigest fixtureをcanonical generatorで更新する。real stdio process testはstore-write-only filtering、start replay、server reconnect、running result、stop cleanup、result redactionを実MCP/runner/CLI processで検証する |

### Issue #315 acceptance mapping

| Current acceptance area | Evidence |
| --- | --- |
| asymmetric capability設定をserver起動時に拒否 | MCP startup capability-closure process tests、catalog profile tests、operation required-capability matrix |
| startはrunning、stopはcleanup後にterminal | core lifecycle tests、verified launcher/production dispatcher tests、real stdio start/stop process test |
| PID、absolute executable、raw status pathを返さない | closed outcome constructor/Serde/schema/contract tests、real process result redaction assertion |
| 不足capabilityでretry/cancelできない | journal/manager capability-digest reauthorization tests、MCP downgraded-server process tests |
| idempotency、restart recovery、cancel、concurrent request | same-key real process replay、completion-intent recovery、operation cancellation、daemon lifecycle lock/concurrent-start tests |
| repository validation | Rust 1.93.1 format、focused core/operation/CLI/MCP suites、workspace Clippy `-D warnings`、`cargo xtask test` |

## Issue #316 resolve-build project-exec evidence

Issue [#316](https://github.com/TamaT-LLC/depgraph-cli/issues/316)は既存の
`resolve --build` orchestrationを共有`DepgraphService`へ移し、
`resolve_build_submit`をdurable operation runnerへ接続する。Issue本文に残る旧要件IDは
現在の[Requirement traceability](#requirement-traceability)表と一致しない。本実装は
`FR-010`（durable handle）、`NFR-001`（bounds/cancel）、`NFR-003`（restart recovery）、
`NFR-005`（host-private情報の非公開）、`AC-014`（baseline/Tasks recovery）、
`AC-015`（CLI/MCP shared-service parity）および`#316`行へ対応付ける。

| Boundary | Frozen behavior and evidence |
| --- | --- |
| Shared project-exec service | CLIとoperation runnerは同じ`DepgraphService::resolve_build_cancellable`を呼ぶ。serviceは`Read + StoreWrite + ProjectExec`をStore open、tool probe、staging、child creationより前に検査し、`acknowledgement=false`を同じpre-mutation位置で拒否する。acknowledgementは既に行われた判断の記録であり、capabilityもAgent hostの独立した人間確認も付与・代替しない |
| Startup compiler authority | MCP serverはbounded regular compiler-pack requirementを起動時に読み、pack manifest・host・target・release checksum bindingを検証する。launcherはそのcanonical requirement pathだけをverified sibling runnerへ渡し、runnerは起動時に再読・再検証する。journalにはabsolute pathではなく検証済みmanifest SHA-256だけを保持し、dispatch直前にもstartup authorityと一致させる |
| Supervised execution | runnerは既存supervisorのstaged workspace、`env_clear`後のallowlist、run-owned output/cache/home/temp、process-tree termination、timeout、cooperative cancellationを使用する。build auditとattemptはStore writer lock内で一度だけ記録し、completed evidenceだけをbase snapshotへatomic promotionする。cancelled/failed/security-failed buildはcurrent snapshotとbuild cacheを更新しない |
| Source mutation boundary | supervisorは実行前後にadmitted original source treeをfingerprintする。postflightの一致に加えて`EnforcedLinuxNamespace`が報告された場合だけ`source_non_mutation_guaranteed=true`である。best-effort hostは一致しても保証せず、`best_effort_isolation_does_not_prevent_source_mutation`を公開diagnosticへ必ず含める。変更検出またはpostflight不能は`security_failed`となり、typed auditへ`source_tree_changed`または`source_postflight_unavailable`を記録してevidence/cacheを破棄する |
| Closed Agent outcome | `AgentBuildOutcome`はbuild ID、closed status、executed/cache-reused、project-code execution、isolation/network strength、source guarantee、最大4件のtyped mutation diagnostics、存在する場合のcompleted snapshot ID、closed host-risk flagsだけを公開する。base scanがないaudit-only buildではoutcomeとenvelopeのsnapshot IDをともに`null`とする。absolute root、command、environment、raw child stream、compiler-pack path、journal inputは公開しない。Deserializerは人間確認責任とacknowledgement非認可をtrueに固定し、best-effortで保証をclaimするpayloadを拒否する |
| Durable failure semantics | project-exec operationがleaseを喪失した場合、journalは外部実行状態を証明できないterminal failureへ進め、handoffをreclaimせず自動再実行しない。request cancel/deadline/lease lossはrunner checkpointから同じservice cancellation tokenへ伝播し、child process treeの終了後だけoperationをcancelledにする |

### Issue #316 acceptance mapping

| Current acceptance area | Evidence |
| --- | --- |
| user拒否、capability不足、acknowledgement=falseでchildを開始しない | CLI consent regression、core missing-capability/false-ack marker test、MCP false-ack missing-store/journal stdio test |
| acknowledgementがstartup capabilityまたは人間確認を代替しない | capability closure、required tool schema、runner startup compiler-pack verification、`AgentBuildHostRisk` semantic validation tests |
| source非変更保証はenforced + successful postflightだけ | supervisor source fingerprint audit、DTO guarantee invariant、schema/Serde tests |
| best-effort違反はtyped audit、lease喪失後は非再実行 | original-source mutation build-script CLI test、security-failed attempt/cache/snapshot assertions、journal/runner lost-lease terminal tests |
| staged/neutral/process-tree/timeout/cancel/atomic attempt | existing build supervisor hostile/cancellation tests、shared service regression、operation runner checkpoints |
| repository validation | Rust 1.93.1 format、focused core/operation/CLI/MCP suites、workspace Clippy `-D warnings`、`cargo xtask test` |

## Issue #317 cross-cutting security E2E evidence

Issue [#317](https://github.com/TamaT-LLC/depgraph-cli/issues/317)は、個別toolの
実装testを置換せず、CLI、live stdio MCP、operation journal/runner、Linux namespace
hostile gateを一つの閉じたsecurity matrixとして横断検証する。Q-002はOption Aで確定済みのため、
baseline-only assertionには置き換えず、Tasksとportable baselineの両reconnect経路を要求する。

| Matrix boundary | Frozen behavior and evidence |
| --- | --- |
| CLI command coverage | 実`clap` parserで23個のleaf commandを最小有効argvから構築し、exhaustive `catalog_action_for_command`へ通す。`ALL_CLI_ACTIONS`とexact一致し、full static catalogで各actionがちょうど一toolへ対応する。新しいleafまたはcatalog actionの未対応・重複はtestまたはcompile-time exhaustive matchで失敗する |
| Static capability discovery | read、store-write、repository-write、daemon-control、project-exec、fullの六profileで実serverの`tools/list`を二回取得し、sorted exact tool名/schemaを比較する。privileged effect toolは必要capabilityのないcatalogへ現れず、名前を直接指定してもargument decode、store、journal、runner、source accessより前にJSON-RPC invalid paramsとなる |
| Cancel and journal integrity | `OperationKind::ALL`の六kindを同じdurable journalへ作成し、read-only serverからの`operation_cancel`が全件`CAPABILITY_DENIED`となること、operation/handoff/tombstoneのcanonical digestとqueued statusが不変であることを確認する。kindを別の有効値へ書き換えたforged recordはget/cancelとも`INTEGRITY_FAILURE`で、repair、claim、executionを行わない |
| Portable path corpus | profile/query/runtime file input、runtime import、repository export output、`path:` selectorを同じPOSIX/Windows相当lexical corpusへ通す。absolute、parent escape、drive prefix、UNC、ADS、device alias、trailing dot/spaceを拒否し、valid/nonexistent symbolic path selectorはfilesystemをdereferenceしない。Unix symlink parent/finalとWindows reparse counterpartはno-follow境界で拒否し、outside destinationを変更しない |
| Prompt and credential handling | query、runtime trace、profile documentのprompt/credential-shaped hostile valueはtyped errorで拒否し、public response、stderr、journalへ反射しない。undiscoverable effectへの同様のpayloadはhandler lookupより先へ進まない |
| Disconnect and recovery | scan、runtime import、export、daemon、resolve-buildの既存real-process/idempotency/restart/cancel test、およびmodern Tasks/legacy baseline reconnect matrixをauthoritative evidenceとして再実行する。server EOFはdurable workを所有せず、same keyは同じID、terminal resultは同じclosed DTOを返す |
| Hostile project execution | dedicated Ubuntu bubblewrap gateは四つのproject-exec gate（static capability、host human confirmation responsibility、acknowledgement、verified compiler-pack authority）、enforced/best-effort claim差、child process-tree termination、original source fingerprint、parent store/private/network canaryを検証する。enforced runのsuccess/timeout後にoriginal digestとexternal canary bytesを再比較する |
| Canonical evidence | `compiler-precise-hostile-e2e-v1` reportの`mcp_security_matrix`は23 CLI actions、六capability profiles、六durable operation kinds、五path boundary、denied cancel/forged operation/source/external canaryのbooleanだけを記録する。host path、input、credential、child streamは含めない |

### Issue #317 acceptance mapping

| Current acceptance area | Evidence |
| --- | --- |
| 全CLI action mappingとeffect discovery gating | real clap/catalog one-to-one unit、全profile live `tools/list` exact process matrix、undiscoverable direct-call pre-state rejection |
| read-only・不足capability cancel不変性 | six-kind cancel process matrix、既存daemon partial-capability test、journal/handoff digestとsource/store不変 assertion |
| 全file input/outputと`path:` selector confinement | combined stdio lexical/symlink/prompt corpus、core portable path unit、Unix symlinkとWindows reparse service tests |
| disconnect/restartとhostile invariant | scan/import/export/daemon/buildの既存idempotency/reconnect/runner suites、Tasks/baseline matrix、dedicated namespace hostile source/external canary assertions |
| repository validation | issue-317 focused suites、compiler-precise hostile gate、workspace Clippy `-D warnings`、`cargo xtask test` |

## Issue #318 five-target MCP release closure

Issue [#318](https://github.com/TamaT-LLC/depgraph-cli/issues/318)は、MCP serverとdurable
operation runnerを既存の5 target native archiveへ追加し、runtime binary、versioned
schema、SDK/protocol metadata、SBOM、license、aggregate attestationを一つのrelease
compatibility unitとして閉じる。Issue本文の旧`NFR-007`と`AC-012`は現在の
[Requirement traceability](#requirement-traceability)表に存在しないため、本節のrelease
closureとfail-closed acceptance evidenceへ対応付ける。

| Release boundary | Frozen behavior and evidence |
| --- | --- |
| Native artifact closure | 全targetで`depgraph-mcp`を`bin/`、`depgraph-operation-runner`を`libexec/`へ配置する。両binaryはworkspace release versionを報告し、manifestは各archive内の実bytesのlowercase SHA-256を保持する。target違いのnative binary digest同一性は要求せず、各targetのchecksum bindingを要求する |
| Tool/operation contract | `schemas/depgraph-mcp-tools-v1.schema.json`をLF-normalized bytesで配布し、tool contract `depgraph-mcp-tools-v1`とportable operation contract `depgraph-operation-v1`をMCP server、runner、schema metadataで相互に固定する。この単一schema catalogはoperation handle、recovery tools、Tasks additive result、全terminal operation outcomeを含む |
| SDK/protocol compatibility | MCP server manifestはSDK `rmcp 3.1.0`とprotocol revision `2026-07-28`をexact valueでattestする。Cargo metadata gateはserverのdirect dependency set、`rmcp =3.1.0`のdefault-off `macros/server/transport-io` features、lockfileで解決した`rmcp-macros 3.1.2`を検証し、version/feature/dependency driftを拒否する |
| SPDX and legal closure | shipped Rust executableのruntime reachability rootへMCP serverを追加し、rmcp、rmcp-macros、server direct dependencyとtransitive closureをSPDX 2.3 SBOMおよびthird-party inventoryへ含める。両rmcp packageはApache-2.0としてexactに記録し、専用noticeはarchive rootの完全な`LICENSE-APACHE`を参照する |
| Aggregate attestation | target reportはMCP server、runner、schema digestとSDK/protocol/tool/operation versionを保持する。5 target aggregateは共通schema digestと互換性metadataの一致を要求し、stable gate schema 8の`mcp-five-target` checkが全digest形式とexact versionを再検証する |
| Fail-closed verification | archive required-file gate、manifest closed deserialization、path confinement、regular/executable bit、actual digest、local binary handshake、locked SBOM/license regenerationを順に検証する。MCP binary/schemaの欠損・改変、SDK/protocol/tool/operation version drift、schema path/contract driftはworker process開始前に拒否する |

### Issue #318 acceptance mapping

| Current acceptance area | Evidence |
| --- | --- |
| 5 targetすべてに二binaryとversioned schema | release build matrix、exact archive paths、required-file/manifest checks、target report digest fields |
| manifest checksumとarchive bytesが一致 | `verify_release_artifact`によるMCP server、runner、schema SHA-256再計算とnative executable check |
| rmcp closure、license、Apache notice | Cargo runtime-root traversal、locked SBOM exact regeneration、rmcp/rmcp-macros exact package assertions、`LICENSE-APACHE` source equality、dedicated notice |
| 欠損・改変・version driftを拒否 | static prelaunch mutation corpus、closed manifest type、Cargo metadata drift unit、aggregate schema-8 MCP gate |
| repository validation | Rust 1.93.1 format、focused xtask/MCP/operation tests、workspace Clippy `-D warnings`、`cargo xtask test` |

## Issue #292 acceptance mapping

| Acceptance criterion | Evidence in this document |
| --- | --- |
| A/Bを根拠付きで選択 | [Q-002 decision](#q-002-decision)でOption Aを比較・採用 |
| Tasks非対応clientのstatus/result回収 | [Portable baseline operation contract](#portable-baseline-operation-contract)で三toolを必須化 |
| negotiation、cancel認可、再接続、compatibility testに未定義分岐なし | 各contract tableと[conformance matrix](#compatibility-and-conformance-tests)で全分岐を固定 |
| Frontmatter、内部link、Markdown、diff check | xtaskのarchitecture decision verifierとrepository validationで検査 |
| 関連test | xtask verifierと後続実装に必須のprotocol/process matrixを定義 |
| `cargo xtask test` | repository validationの必須gate |
