---
id: PROJ-ARC-002
layer: L4
feature: mcp-agent-tools
scope: feature
status: Active
upstream: [PROJ-ARC-001]
downstream: []
owner: TakehiroT
updated: 2026-08-05
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
| Open questions | `0` | Resolved |

Stage 1ではcontractをfreezeする。operation journal、runner、baseline operation
tools、Tasks adapterの実装は後続taskで行い、この文書のnegotiationとrecovery
semanticsを変更してはならない。

## Requirement traceability

| ID | Requirement | Resolution |
| --- | --- | --- |
| `FR-010` | 長時間処理は切断後もstatus、terminal result、cancelを回収できるdurable handleを返す | baseline operation toolsを全hostに必須とし、Tasksは同じrecordへの追加mappingとする |
| `NFR-003` | host差、切断、server restartをfailureとして回収できる | journalをstdio processとrmcp runtimeから独立させ、再接続時に同じIDを解決する |
| `Q-002` | baseline handleへMCP Tasksを追加するか | **Resolved: Option Aを採用する** |
| `AC-014` | Tasks非対応hostを含め、accepted operationのstatus、result、cancelが未定義分岐なく機能する | capability matrix、result union、認可、再接続、互換性test matrixを本書で固定する |

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

## Issue #292 acceptance mapping

| Acceptance criterion | Evidence in this document |
| --- | --- |
| A/Bを根拠付きで選択 | [Q-002 decision](#q-002-decision)でOption Aを比較・採用 |
| Tasks非対応clientのstatus/result回収 | [Portable baseline operation contract](#portable-baseline-operation-contract)で三toolを必須化 |
| negotiation、cancel認可、再接続、compatibility testに未定義分岐なし | 各contract tableと[conformance matrix](#compatibility-and-conformance-tests)で全分岐を固定 |
| Frontmatter、内部link、Markdown、diff check | xtaskのarchitecture decision verifierとrepository validationで検査 |
| 関連test | xtask verifierと後続実装に必須のprotocol/process matrixを定義 |
| `cargo xtask test` | repository validationの必須gate |
