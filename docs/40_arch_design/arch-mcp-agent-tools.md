---
id: PROJ-ARC-002
layer: L4
feature: mcp-agent-tools
scope: feature
status: Active
upstream: [PROJ-ARC-001]
downstream: []
owner: TakehiroT
updated: 2026-08-07
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

## Issue #292 acceptance mapping

| Acceptance criterion | Evidence in this document |
| --- | --- |
| A/Bを根拠付きで選択 | [Q-002 decision](#q-002-decision)でOption Aを比較・採用 |
| Tasks非対応clientのstatus/result回収 | [Portable baseline operation contract](#portable-baseline-operation-contract)で三toolを必須化 |
| negotiation、cancel認可、再接続、compatibility testに未定義分岐なし | 各contract tableと[conformance matrix](#compatibility-and-conformance-tests)で全分岐を固定 |
| Frontmatter、内部link、Markdown、diff check | xtaskのarchitecture decision verifierとrepository validationで検査 |
| 関連test | xtask verifierと後続実装に必須のprotocol/process matrixを定義 |
| `cargo xtask test` | repository validationの必須gate |
