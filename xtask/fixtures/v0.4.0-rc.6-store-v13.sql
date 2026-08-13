-- Captured with the official v0.4.0-rc.6 aarch64-apple-darwin packaged CLI
-- from tag commit bb5dbe67e737cf50f07d90e6f4c8b7658c631184.
-- Source archive SHA-256: 9dfde55ce04f940464c1d9215d165fb6786264f1b40fe4dd2c01a7b210eb18c3.
-- Packaged binary SHA-256: c7d97ea0b2f4af388b6cd3ad7b69f41ac1ac5df65dadf7c20f749d4082f0fca4.
-- The packaged CLI transactionally migrated the official v0.4.0-rc.1
-- schema-11 fixture to schema 13 without changing its completed graph identity.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    root TEXT NOT NULL,
    status TEXT NOT NULL,
    strict INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    project_code_executed INTEGER NOT NULL DEFAULT 0,
    protocol_version TEXT NOT NULL,
    error TEXT
, parent_snapshot_id TEXT, source_revision TEXT, mutation_count INTEGER NOT NULL DEFAULT 0);
INSERT INTO scans VALUES('official-v0.4.0-rc.1-scan','/fixture/v0.4.0-rc.1','completed',0,'2026-07-23T22:21:48.184Z','2026-07-23T22:21:49.298Z',0,'1.0',NULL,NULL,NULL,0);
CREATE TABLE current_successful (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    scan_id TEXT NOT NULL REFERENCES scans(id)
);
INSERT INTO current_successful VALUES(1,'official-v0.4.0-rc.1-scan');
CREATE TABLE profiles (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
INSERT INTO profiles VALUES('official-v0.4.0-rc.1-scan','profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9','{"id":"profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9","language":"go","toolchain":"go1.26.1","command":"scan","target":"darwin-arm64","features":[],"environment":{"CGO_ENABLED":"0","GOARCH":"arm64","GOOS":"darwin","GO_TAGS":""},"properties":{"configured_tags":"","go_call_graph_effective_algorithms":"","go_call_graph_library_partial":"cha","go_call_graph_main_test":"rta","go_call_graph_requested":"rta-cha","go_call_graph_vta_engine":"golang.org/x/tools/go/callgraph/vta@v0.48.0","go_call_graph_vta_prerequisites":"complete-program,instantiate-generics,serial-ssa","go_call_graph_vta_status":"not-requested","go_callgraph_boundary_completeness_policy":"semantic-complete-allowed-with-explicit-boundaries","go_callgraph_boundary_counts":"","go_callgraph_boundary_kinds":"","go_callgraph_boundary_site_count":"0","go_callgraph_boundary_status":"none","go_dependency_snapshot_files":"1","go_dependency_snapshot_fingerprint":"go_dependency_snapshot:sha256:26367fe3faf73564b3e07232d0dd7e9166b6765ddeefd9afc0c46cffb379af19","go_dependency_snapshot_modules":"1","go_dependency_snapshot_packages":"1","go_dependency_snapshot_schema":"go-offline-dependency-snapshot-v1","go_dependency_snapshot_status":"complete","go_packages_active_files":"2","go_packages_compiled_files":"2","go_packages_embed_files":"0","go_packages_modules":"2","go_packages_packages":"2","go_packages_query":"syntax-types-types-info","go_packages_safe_mode":"offline,readonly,no-external-driver,cgo-disabled,telemetry-disabled","go_packages_status":"loaded","go_packages_test_variants":"0","go_packages_typed_files":"2","go_packages_typed_packages":"2","go_ssa_builder_mode":"instantiate-generics,serial","safe_scan":"true","variants":"normal,internal_test,external_test"}}');
CREATE TABLE nodes (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    kind TEXT NOT NULL,
    locator TEXT NOT NULL,
    display_name TEXT NOT NULL,
    properties_json TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
INSERT INTO nodes VALUES('official-v0.4.0-rc.1-scan','file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead','file','file:main.go','main.go','{"build_constraint":"","generated":false,"language":"go","package_name":"main","package_path":"example.com/dependency-snapshot-app","test":false}','{"id":"file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead","kind":"file","locator":"file:main.go","display_name":"main.go","properties":{"build_constraint":"","generated":false,"language":"go","package_name":"main","package_path":"example.com/dependency-snapshot-app","test":false}}');
INSERT INTO nodes VALUES('official-v0.4.0-rc.1-scan','module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0','module','go-package:example.com/dependency-snapshot-dep','example.com/dependency-snapshot-dep','{"language":"go","module_path":"example.com/dependency-snapshot-dep","package_name":"dep","relative_dir":"dep","vendor":false}','{"id":"module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0","kind":"module","locator":"go-package:example.com/dependency-snapshot-dep","display_name":"example.com/dependency-snapshot-dep","properties":{"language":"go","module_path":"example.com/dependency-snapshot-dep","package_name":"dep","relative_dir":"dep","vendor":false}}');
CREATE TABLE sites (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    specifier TEXT,
    profile_id TEXT NOT NULL,
    resolution_status TEXT NOT NULL,
    precision TEXT NOT NULL,
    condition_json TEXT NOT NULL,
    target_ids_json TEXT NOT NULL,
    reason TEXT,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
INSERT INTO sites VALUES('official-v0.4.0-rc.1-scan','site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc','file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead','import','example.com/dependency-snapshot-dep','profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9','resolved','exact','{"op":"all","conditions":[]}','["module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0"]',NULL,'{"id":"site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc","source":"file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead","kind":"import","specifier":"example.com/dependency-snapshot-dep","resolution_status":"resolved","target_ids":["module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0"],"profile_id":"profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9","condition":{"op":"all","conditions":[]},"precision":"exact","evidence":[{"kind":"source","extractor":"go-static-worker","extractor_version":"0.4.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}]}');
CREATE TABLE edges (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    site_id TEXT,
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    kind TEXT NOT NULL,
    phase TEXT NOT NULL,
    environment TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    resolution_status TEXT NOT NULL,
    precision TEXT NOT NULL,
    condition_json TEXT NOT NULL,
    generated INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id),
    FOREIGN KEY (scan_id, site_id) REFERENCES sites(scan_id, id)
);
INSERT INTO edges VALUES('official-v0.4.0-rc.1-scan','edge:sha256:0c695eef30a2ae3466742ff5738377269b0eb5974efaa74c1b5ad2dd400f387f','site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc','file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead','module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0','imports','source','any','profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9','resolved','exact','{"op":"all","conditions":[]}',0,'{"id":"edge:sha256:0c695eef30a2ae3466742ff5738377269b0eb5974efaa74c1b5ad2dd400f387f","source":"file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead","target":"module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0","kind":"imports","site_id":"site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc","phase":"source","environment":"any","profile_id":"profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9","condition":{"op":"all","conditions":[]},"resolution_status":"resolved","precision":"exact","generated":false,"evidence":[{"kind":"source","extractor":"go-static-worker","extractor_version":"0.4.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}]}');
CREATE TABLE evidence (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    owner_type TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL,
    extractor TEXT NOT NULL,
    extractor_version TEXT NOT NULL,
    path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    start_column INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_column INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, owner_type, owner_id, ordinal)
);
INSERT INTO evidence VALUES('official-v0.4.0-rc.1-scan','site','site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc',0,'source','go-static-worker','0.2.0-rc.1','main.go',3,8,3,45,'{"kind":"source","extractor":"go-static-worker","extractor_version":"0.4.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}');
INSERT INTO evidence VALUES('official-v0.4.0-rc.1-scan','edge','edge:sha256:0c695eef30a2ae3466742ff5738377269b0eb5974efaa74c1b5ad2dd400f387f',0,'source','go-static-worker','0.2.0-rc.1','main.go',3,8,3,45,'{"kind":"source","extractor":"go-static-worker","extractor_version":"0.4.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}');
CREATE TABLE diagnostics (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    id TEXT NOT NULL,
    severity TEXT NOT NULL,
    code TEXT NOT NULL,
    message TEXT NOT NULL,
    path TEXT,
    adapter TEXT,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (scan_id, ordinal),
    UNIQUE (scan_id, id)
);
CREATE TABLE file_coverage (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    discovered_sites INTEGER NOT NULL,
    emitted_sites INTEGER NOT NULL,
    skipped_sites INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL,
    reason TEXT,
    adapter TEXT NOT NULL,
    PRIMARY KEY (scan_id, adapter, path)
);
INSERT INTO file_coverage VALUES('official-v0.4.0-rc.1-scan','main.go',2,2,0,0,NULL,'go');
CREATE TABLE coverage (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    json TEXT NOT NULL
);
INSERT INTO coverage VALUES('official-v0.4.0-rc.1-scan','{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete","semantic-complete"],"reasons":[]}');
CREATE TABLE adapter_logs (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    adapter TEXT NOT NULL,
    stderr TEXT NOT NULL,
    truncated INTEGER NOT NULL,
    PRIMARY KEY (scan_id, adapter)
);
CREATE TABLE profile_coverage (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (scan_id, profile_id)
);
INSERT INTO profile_coverage VALUES('official-v0.4.0-rc.1-scan','profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9','{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete","semantic-complete"],"reasons":[]}');
CREATE TABLE build_audits (
                    run_id TEXT PRIMARY KEY,
                    outcome TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    audit_json TEXT NOT NULL
                 );
CREATE TABLE build_attempts (
                    id TEXT PRIMARY KEY,
                    base_scan_id TEXT NOT NULL REFERENCES scans(id),
                    audit_run_id TEXT NOT NULL UNIQUE REFERENCES build_audits(run_id),
                    status TEXT NOT NULL,
                    observer TEXT NOT NULL,
                    observer_version TEXT NOT NULL,
                    profile_id TEXT NOT NULL,
                    command_plan_digest TEXT NOT NULL,
                    toolchain_executable_digest TEXT NOT NULL,
                    environment_key_set_digest TEXT NOT NULL,
                    validated_output_digest TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    delta_json TEXT
                 , base_snapshot_id TEXT);
CREATE TABLE current_build_successful (
                    base_scan_id TEXT PRIMARY KEY REFERENCES scans(id),
                    attempt_id TEXT NOT NULL UNIQUE REFERENCES build_attempts(id)
                 );
CREATE TABLE current_completed_snapshot (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id)
                 );
INSERT INTO current_completed_snapshot VALUES(1,'snapshot:sha256:9586aa1acd653d75c867037b8d7ebc16241c29197b32217eb878e5f46888dd28');
CREATE TABLE snapshot_names (
                    name TEXT PRIMARY KEY COLLATE NOCASE,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                    named_at TEXT NOT NULL
                 );
CREATE TABLE syntax_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
CREATE TABLE semantic_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
CREATE TABLE build_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    dimensions_json TEXT NOT NULL,
                    snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
CREATE TABLE cache_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
                    build_attempt_id TEXT REFERENCES build_attempts(id) ON DELETE CASCADE,
                    layer TEXT NOT NULL CHECK (layer IN ('syntax', 'semantic', 'build')),
                    cache_key TEXT,
                    outcome TEXT NOT NULL CHECK (outcome IN ('hit', 'miss', 'reject', 'stored')),
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    CHECK ((scan_id IS NOT NULL AND build_attempt_id IS NULL)
                        OR (scan_id IS NULL AND build_attempt_id IS NOT NULL))
                 );
CREATE TABLE IF NOT EXISTS "completed_snapshots" (
                        id TEXT PRIMARY KEY,
                        source_kind TEXT NOT NULL
                            CHECK (source_kind IN ('scan', 'build', 'runtime')),
                        source_attempt_id TEXT NOT NULL,
                        scan_id TEXT NOT NULL REFERENCES scans(id),
                        build_attempt_id TEXT REFERENCES build_attempts(id),
                        runtime_import_id TEXT,
                        runtime_session_set_json TEXT NOT NULL DEFAULT '[]',
                        parent_snapshot_id TEXT REFERENCES "completed_snapshots"(id),
                        source_revision TEXT,
                        profile_set_json TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status = 'completed'),
                        created_at TEXT NOT NULL,
                        CHECK (
                            (source_kind = 'scan'
                                AND build_attempt_id IS NULL
                                AND runtime_import_id IS NULL
                                AND runtime_session_set_json = '[]')
                            OR (source_kind = 'build'
                                AND build_attempt_id IS NOT NULL
                                AND runtime_import_id IS NULL)
                            OR (source_kind = 'runtime'
                                AND runtime_import_id IS NOT NULL
                                AND runtime_session_set_json != '[]')
                        )
                     );
INSERT INTO completed_snapshots VALUES('snapshot:sha256:9586aa1acd653d75c867037b8d7ebc16241c29197b32217eb878e5f46888dd28','scan','official-v0.4.0-rc.1-scan','official-v0.4.0-rc.1-scan',NULL,NULL,'[]',NULL,NULL,'["profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9"]','completed','2026-07-23T22:21:49.298Z');
CREATE TABLE IF NOT EXISTS "snapshot_sources" (
                        source_kind TEXT NOT NULL
                            CHECK (source_kind IN ('scan', 'build', 'runtime')),
                        source_attempt_id TEXT NOT NULL,
                        snapshot_id TEXT NOT NULL
                            REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                        promoted_at TEXT NOT NULL,
                        PRIMARY KEY (source_kind, source_attempt_id)
                     );
INSERT INTO snapshot_sources VALUES('scan','official-v0.4.0-rc.1-scan','snapshot:sha256:9586aa1acd653d75c867037b8d7ebc16241c29197b32217eb878e5f46888dd28','2026-07-23T22:21:49.298Z');
CREATE TABLE runtime_sessions (
                        id TEXT PRIMARY KEY,
                        base_snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                        source_session_id TEXT NOT NULL,
                        schema_version TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('completed', 'partial')),
                        trace_digest TEXT NOT NULL,
                        profile_id TEXT NOT NULL,
                        parent_profile_id TEXT,
                        profile_status TEXT NOT NULL,
                        profile_reason TEXT,
                        profile_json TEXT NOT NULL,
                        environment_json TEXT NOT NULL,
                        redaction_json TEXT NOT NULL,
                        started_at TEXT NOT NULL,
                        ended_at TEXT,
                        first_observed_at TEXT NOT NULL,
                        last_observed_at TEXT NOT NULL,
                        event_count INTEGER NOT NULL,
                        observation_count INTEGER NOT NULL,
                        resolved_targets INTEGER NOT NULL,
                        external_targets INTEGER NOT NULL,
                        unresolved_targets INTEGER NOT NULL,
                        redacted_values INTEGER NOT NULL,
                        coverage_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                     );
CREATE TABLE runtime_nodes (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, id)
                     );
CREATE TABLE runtime_sites (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, id)
                     );
CREATE TABLE runtime_edges (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, id)
                     );
CREATE TABLE runtime_evidence (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        owner_type TEXT NOT NULL,
                        owner_id TEXT NOT NULL,
                        ordinal INTEGER NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, owner_type, owner_id, ordinal)
                     );
CREATE TABLE runtime_diagnostics (
                        session_id TEXT NOT NULL
                            REFERENCES runtime_sessions(id) ON DELETE CASCADE,
                        ordinal INTEGER NOT NULL,
                        id TEXT NOT NULL,
                        raw_json TEXT NOT NULL,
                        PRIMARY KEY (session_id, ordinal),
                        UNIQUE (session_id, id)
                     );
CREATE TABLE runtime_imports (
                        id TEXT PRIMARY KEY,
                        parent_snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                        session_id TEXT NOT NULL REFERENCES runtime_sessions(id),
                        status TEXT NOT NULL CHECK (status IN ('staging', 'completed', 'failed')),
                        result_snapshot_id TEXT REFERENCES completed_snapshots(id),
                        created_at TEXT NOT NULL,
                        completed_at TEXT,
                        error TEXT
                     );
CREATE TABLE incremental_deltas (
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    delta_id TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    base_snapshot_id TEXT NOT NULL REFERENCES completed_snapshots(id),
                    base_graph_digest TEXT NOT NULL,
                    result_graph_digest TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    mutation_count INTEGER NOT NULL CHECK (mutation_count > 0),
                    status TEXT NOT NULL
                        CHECK (status IN ('staging', 'applied', 'failed', 'cancelled')),
                    prospective_snapshot_id TEXT,
                    staged_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT,
                    PRIMARY KEY (scan_id, delta_id)
                 );
CREATE TABLE impact_query_cache (
                    key TEXT PRIMARY KEY,
                    contract_version INTEGER NOT NULL,
                    snapshot_id TEXT NOT NULL
                        REFERENCES completed_snapshots(id) ON DELETE CASCADE,
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    last_used_sequence INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                 );
CREATE TRIGGER snapshot_names_immutable_update
                    BEFORE UPDATE ON snapshot_names
                    BEGIN SELECT RAISE(ABORT, 'snapshot names are immutable'); END;
CREATE TRIGGER snapshot_names_immutable_delete
                    BEFORE DELETE ON snapshot_names
                    BEGIN SELECT RAISE(ABORT, 'snapshot names are immutable'); END;
CREATE INDEX nodes_scan_kind ON nodes(scan_id, kind);
CREATE INDEX nodes_scan_locator ON nodes(scan_id, locator);
CREATE INDEX sites_scan_status ON sites(scan_id, resolution_status);
CREATE INDEX edges_scan_source ON edges(scan_id, source);
CREATE INDEX edges_scan_target ON edges(scan_id, target);
CREATE INDEX edges_scan_kind ON edges(scan_id, kind);
CREATE INDEX edges_scan_site ON edges(scan_id, site_id);
CREATE INDEX evidence_scan_path ON evidence(scan_id, path);
CREATE INDEX build_audits_started_at
                    ON build_audits(started_at, run_id);
CREATE INDEX build_attempts_base_status
                    ON build_attempts(base_scan_id, status, started_at, id);
CREATE INDEX snapshot_names_snapshot
                    ON snapshot_names(snapshot_id, name);
CREATE INDEX cache_events_scan_created
                    ON cache_events(scan_id, created_at, id);
CREATE INDEX cache_events_build_created
                    ON cache_events(build_attempt_id, created_at, id);
CREATE INDEX completed_snapshots_scan_created
                        ON completed_snapshots(scan_id, created_at, id);
CREATE INDEX completed_snapshots_parent
                        ON completed_snapshots(parent_snapshot_id, id);
CREATE INDEX snapshot_sources_snapshot
                        ON snapshot_sources(snapshot_id, source_kind, source_attempt_id);
CREATE INDEX runtime_sessions_base_created
                        ON runtime_sessions(base_snapshot_id, created_at, id);
CREATE INDEX runtime_sessions_profile
                        ON runtime_sessions(profile_id, id);
CREATE INDEX runtime_edges_session_source
                        ON runtime_edges(session_id, id);
CREATE INDEX runtime_evidence_owner
                        ON runtime_evidence(owner_type, owner_id, session_id, ordinal);
CREATE INDEX runtime_imports_parent_created
                        ON runtime_imports(parent_snapshot_id, created_at, id);
CREATE INDEX incremental_deltas_base_status
                    ON incremental_deltas(base_snapshot_id, status, staged_at, scan_id, delta_id);
CREATE INDEX impact_query_cache_snapshot_used
                    ON impact_query_cache(snapshot_id, last_used_sequence, key);
CREATE INDEX impact_query_cache_lru
                    ON impact_query_cache(last_used_sequence, key);
PRAGMA user_version=13;
COMMIT;
