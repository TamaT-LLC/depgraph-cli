# depgraph Agent dogfood task corpus v1

You are evaluating dependency-analysis evidence in a repository fixed at commit
`85dcf029ad4d536b1ffa5f9b148749f2beb95128`. Work read-only. Do not edit files,
run a scan, invoke a depgraph CLI binary, submit an operation, start or stop a
daemon, or execute project code. Read-only source and Git inspection are allowed.
If the `depgraph` MCP server is available, use only its read-capability tools;
you may combine those graph results with the same read-only source and Git
inspection available to the baseline arm. Every MCP run must complete the
ordered claim plan and call all eight required workflow tools:
`agent_nodes_list`, `get_context`, `graph_cycles_list`,
`graph_dependencies_list`, `graph_dependents_list`, `graph_impact_get`,
`graph_path_get`, and `snapshot_diff_get`.
If it is absent, that is the intended baseline condition, not a setup blocker or
missing-tool failure: investigate with read-only source and Git commands, mark
facts that cannot be established without graph evidence as `insufficient`, and
leave the top-level failure at `code: "none"`.

The MCP logical repository ID is `repository`. Its immutable snapshots are
`agent-tools-baseline` (commit `ccd71620deb53161b5856c8e93fecae4ffdf163c`)
and `rc7-candidate` (the candidate commit above). Use `rc7-candidate` unless a
task explicitly asks for a diff. Keep the investigation within 28 tool calls.
For comparable accounting, one tool call may investigate at most one numbered
claim. Do not join unrelated commands, targets, or claim investigations in one
shell invocation. Every source/Git shell invocation must contain exactly one
`git`, `rg`, or `sed` command, with no shell chaining, pipeline, substitution,
redirection, or project executable. Unrecognized commands conservatively fail
the read-only safety gate.

For this fixed large snapshot, use `path:<repository-relative-path>` for file
selectors. Set `max_traversal` to `1000000` for dependency, path, and cycle
queries, and use `max_nodes: 1000000` plus `max_edges: 1000000` for impact.
Use a page limit of 10 for the targeted dependency/dependent/impact/cycle
queries: every requested target fact is present in that first canonical page.
`snapshot_diff_get` is not paginated; call it once per requested kind and use
its aggregate fields, collection digest, and returned changes without repeating
the call. When an edge exposes only a stable node ID and the canonical non-file
locator is required, an exact `agent_nodes_list` lookup can resolve that ID. If
the public node DTO deliberately falls back to an `id:` locator, use the graph
evidence together with read-only source inspection rather than guessing.

Apply these public-result rendering rules consistently:

- Resolve the Rust `catalog` module with `agent_nodes_list` before asking for
  its path. Do not first try a bare display-name selector.
- Immediately after the Go dependency query and each of the two targeted Rust
  edge queries, resolve the returned non-file target ID with one exact
  `agent_nodes_list` call and retain that locator. Do not repeat the dependency
  query later. Do not use `agent_nodes_list` for the Web file target or incoming
  Web file/package source IDs; use the rendering/source rules below.
- A TypeScript/Web file endpoint is rendered as `file://<repository_path>`; a
  Rust file impact endpoint is rendered as `file:<repository_path>`. Do not
  query a returned file ID merely to recover a locator when graph evidence or
  an `AgentNode.repository_path` already provides the path.
- Direct incoming edges include every edge kind, including `contains`. When a
  package endpoint has no public repository path, render the public fallback
  locator as `id:<source_id>` exactly. Never prefix an `id:` fallback with
  `package://`, and do not inspect private worker implementation to recover a
  non-public locator. Sort the final rendered source locators, not the raw IDs
  or discovery order.
- For the package snapshot diff, report the directly returned `total_changes`,
  `empty`, and `collection_digest`. For the large file diff, report only its
  top-level `collection_digest`; it remains authoritative even if the host
  elides part of the 288-item `changes` array. Do not recount that array and do
  not mark the file-diff claim insufficient when the digest is present.
- Render Web file-cycle nodes as `file://<repository_path>`, then rotate the
  cycle as requested. If the cycle DTO exposes only node IDs, use at most one
  bounded source command across `workers/web/src` to investigate that single
  claim; related files for one claim may be inspected together. Source imports
  alone do not prove which repository paths correspond to opaque graph IDs. If
  no public result establishes that correspondence, you MUST report the claim
  as `insufficient`/`not_applicable`/`unknown`; never choose a plausible source
  cycle and label it exact. Run separate file- and package-level cycle queries.
- In candidate coverage, map `files` to `files_analyzed`, `sites` to
  `dependency_sites`, and `unsupported` to `unsupported_syntax`.
- Deterministic snapshot-diff, cycle-count, and snapshot-coverage results use
  classification `exact`, including empty/zero aggregate results.

Reserve the final two tool calls for the package-level cycle query and
`get_context`. Once the requested fact is established, do not spend additional
calls rechecking it.

When MCP is available, execute this claim plan in order. Do not substitute node
discovery for a graph query that already accepts a `path:` selector:

1. For `rust_path`, call `agent_nodes_list` with query `catalog`, match mode
   `exact`, and limit 10. Select the returned Rust module locator, then call
   `graph_path_get` from the requested `path:` selector to that locator.
2. For `go_dependency`, call `graph_dependencies_list` on the Go file `path:`
   selector, then immediately resolve the line-10 edge target ID with exact
   `agent_nodes_list`.
3. For `web_dependency`, call `graph_dependencies_list` on `worker.ts`; use the
   line-17 graph edge and the Web file rendering rule. Do not node-query its
   file target ID.
4. For `web_dependents`, call `graph_dependents_list` on `scanner.ts`; project
   file sources from evidence paths and the package source as `id:<source_id>`.
5. For `rust_impact`, call `graph_impact_get` directly on the catalog file
   `path:` selector.
6. For `rust_unresolved_type`, call `graph_dependencies_list` directly on
   `crates/depgraph-mcp/src/main.rs` via `path:`, select line 2064, then resolve
   that edge target ID with exact `agent_nodes_list`.
7. For `rust_candidate_import`, do the same on
   `crates/depgraph-cli/src/main.rs` at line 2704.
8. Call `snapshot_diff_get` once for package and once for file.
9. Call `graph_cycles_list` for file. If it returns opaque IDs, use exactly one
   source command:
   `rg -n '^import .*from ' workers/web/src --glob '*.ts'`.
10. Call `graph_cycles_list` for package, then call `get_context` for coverage.

Never call `agent_nodes_list` with a repository path, a `path:` query, or
`match_mode: contains`; file source lookup through that route is invalid for
this packaged snapshot. A typed failure from one optional lookup is not a reason
to skip the direct graph query for another claim.

Return every claim in the supplied JSON response schema. Use `supported` only
when the evidence establishes the requested graph fact, `refuted` when it
establishes the opposite, and `insufficient` otherwise. A source-level fact
alone does not establish depgraph's resolution status or precision. Use the
graph's own `exact`, `candidate`, `unresolved`, `external`, or `heuristic`
classification; never promote a candidate or unresolved edge to exact. For an
insufficient answer, use classification `not_applicable` and value `unknown`.
Set the top-level failure to `code: "none"` with empty task and remediation
when the host can complete the run; otherwise use one typed failure code and a
concrete remediation.
Use the exact value format requested below, without Markdown.

1. `rust_path`: Find the shortest candidate-snapshot path from
   `crates/depgraph-mcp-tools/src/lib.rs` to the Rust `catalog` module. Value:
   `target=<locator>;steps=<decimal>;kind=<edge-kind>`.
2. `go_dependency`: Identify the internal Go package imported by
   `workers/go/cmd/depgraph-go-worker/main.go`, including its evidence line.
   Value: `target=<locator>;line=<decimal>;kind=<edge-kind>`.
3. `web_dependency`: Identify the `scanner.ts` dependency of
   `workers/web/src/worker.ts`, including line and rendered condition. Value:
   `target=<locator>;line=<decimal>;condition=<condition>`.
4. `web_dependents`: List every direct incoming source locator for
   `workers/web/src/scanner.ts`, sorted lexicographically. Value:
   `count=<decimal>;sources=<comma-separated-locators>`.
5. `rust_impact`: For a change to
   `crates/depgraph-mcp-tools/src/catalog.rs`, list every non-root impacted
   locator through depth 2 with its depth, sorted lexicographically by locator.
   Value: `complete=<true-or-false>;items=<locator>@<depth>,...`.
6. `rust_unresolved_type`: Classify the `DepgraphService` type-use edge at
   `crates/depgraph-mcp/src/main.rs:2064`. Value:
   `target=<locator>;status=<status>;precision=<precision>;line=<decimal>`.
7. `rust_candidate_import`: Classify the `use super` import edge at
   `crates/depgraph-cli/src/main.rs:2704`. Value:
   `target=<locator>;status=<status>;precision=<precision>;line=<decimal>`.
8. `snapshot_package_diff`: Diff baseline to candidate with kind `package`.
   Value: `total=<decimal>;empty=<true-or-false>;digest=<collection-digest>`.
9. `snapshot_file_diff`: Diff baseline to candidate with kind `file`. Value:
   `digest=<collection-digest>`.
10. `file_cycle`: Find the candidate file-level cycle and rotate it to start and
    end at `workers/web/src/imports.ts`. Value:
    `count=<decimal>;cycle=<locator>-><locator>->...-><locator>`.
11. `package_cycles`: Count candidate package-level cycles. Value:
    `count=<decimal>`.
12. `candidate_coverage`: Report candidate snapshot coverage. Value:
    `files=<decimal>;sites=<decimal>;resolved=<decimal>;candidates=<decimal>;external=<decimal>;unresolved=<decimal>;unsupported=<decimal>;project_code_executed=<true-or-false>`.

Evidence paths must be repository-relative. Keep reasons concise and do not
include absolute paths, credentials, prompts, environment values, or raw graph
properties. Every supported or refuted dependency/path/dependent/impact/
unresolved/candidate/cycle claim must include one to three evidence entries.
Aggregate-only snapshot diff, zero-cycle, and coverage claims may use an empty
evidence array when their MCP result has no repository path. Insufficient claims
may also use an empty evidence array.
