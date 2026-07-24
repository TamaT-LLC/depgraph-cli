-- Produced with the official v0.2.0-rc.1 aarch64-apple-darwin archive,
-- then reduced to one completed dependency without changing the v5 layout.
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
);
INSERT INTO scans VALUES(
    'legacy-v0.2.0-rc.1-scan',
    '/fixture/v0.2.0-rc.1',
    'completed',
    0,
    '2026-07-23T22:21:48.184Z',
    '2026-07-23T22:21:49.298Z',
    0,
    '1.0',
    NULL
);
CREATE TABLE current_successful (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    scan_id TEXT NOT NULL REFERENCES scans(id)
);
INSERT INTO current_successful VALUES(1,'legacy-v0.2.0-rc.1-scan');
CREATE TABLE profiles (
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    json TEXT NOT NULL,
    PRIMARY KEY (scan_id, id)
);
INSERT INTO profiles VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9',
    '{"id":"profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9","language":"go","toolchain":"go1.26.1","command":"scan","target":"darwin-arm64","features":[],"environment":{"CGO_ENABLED":"0","GOARCH":"arm64","GOOS":"darwin","GO_TAGS":""},"properties":{"configured_tags":"","go_call_graph_effective_algorithms":"","go_call_graph_library_partial":"cha","go_call_graph_main_test":"rta","go_call_graph_requested":"rta-cha","go_call_graph_vta_engine":"golang.org/x/tools/go/callgraph/vta@v0.48.0","go_call_graph_vta_prerequisites":"complete-program,instantiate-generics,serial-ssa","go_call_graph_vta_status":"not-requested","go_callgraph_boundary_completeness_policy":"semantic-complete-allowed-with-explicit-boundaries","go_callgraph_boundary_counts":"","go_callgraph_boundary_kinds":"","go_callgraph_boundary_site_count":"0","go_callgraph_boundary_status":"none","go_dependency_snapshot_files":"1","go_dependency_snapshot_fingerprint":"go_dependency_snapshot:sha256:26367fe3faf73564b3e07232d0dd7e9166b6765ddeefd9afc0c46cffb379af19","go_dependency_snapshot_modules":"1","go_dependency_snapshot_packages":"1","go_dependency_snapshot_schema":"go-offline-dependency-snapshot-v1","go_dependency_snapshot_status":"complete","go_packages_active_files":"2","go_packages_compiled_files":"2","go_packages_embed_files":"0","go_packages_modules":"2","go_packages_packages":"2","go_packages_query":"syntax-types-types-info","go_packages_safe_mode":"offline,readonly,no-external-driver,cgo-disabled,telemetry-disabled","go_packages_status":"loaded","go_packages_test_variants":"0","go_packages_typed_files":"2","go_packages_typed_packages":"2","go_ssa_builder_mode":"instantiate-generics,serial","safe_scan":"true","variants":"normal,internal_test,external_test"}}'
);
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
INSERT INTO nodes VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead',
    'file',
    'file:main.go',
    'main.go',
    '{"build_constraint":"","generated":false,"language":"go","package_name":"main","package_path":"example.com/dependency-snapshot-app","test":false}',
    '{"id":"file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead","kind":"file","locator":"file:main.go","display_name":"main.go","properties":{"build_constraint":"","generated":false,"language":"go","package_name":"main","package_path":"example.com/dependency-snapshot-app","test":false}}'
);
INSERT INTO nodes VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0',
    'module',
    'go-package:example.com/dependency-snapshot-dep',
    'example.com/dependency-snapshot-dep',
    '{"language":"go","module_path":"example.com/dependency-snapshot-dep","package_name":"dep","relative_dir":"dep","vendor":false}',
    '{"id":"module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0","kind":"module","locator":"go-package:example.com/dependency-snapshot-dep","display_name":"example.com/dependency-snapshot-dep","properties":{"language":"go","module_path":"example.com/dependency-snapshot-dep","package_name":"dep","relative_dir":"dep","vendor":false}}'
);
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
INSERT INTO sites VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc',
    'file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead',
    'import',
    'example.com/dependency-snapshot-dep',
    'profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9',
    'resolved',
    'exact',
    '{"op":"all","conditions":[]}',
    '["module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0"]',
    NULL,
    '{"id":"site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc","source":"file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead","kind":"import","specifier":"example.com/dependency-snapshot-dep","resolution_status":"resolved","target_ids":["module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0"],"profile_id":"profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9","condition":{"op":"all","conditions":[]},"precision":"exact","evidence":[{"kind":"source","extractor":"go-static-worker","extractor_version":"0.2.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}]}'
);
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
INSERT INTO edges VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'edge:sha256:0c695eef30a2ae3466742ff5738377269b0eb5974efaa74c1b5ad2dd400f387f',
    'site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc',
    'file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead',
    'module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0',
    'imports',
    'source',
    'any',
    'profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9',
    'resolved',
    'exact',
    '{"op":"all","conditions":[]}',
    0,
    '{"id":"edge:sha256:0c695eef30a2ae3466742ff5738377269b0eb5974efaa74c1b5ad2dd400f387f","source":"file:sha256:52c8d93f1c6a95f5ac21789712ec3a06f20bff5dcba71f82250e137928f27ead","target":"module:sha256:3461db6d003d14c3bf3b4db407e83366f737008c0d0d9735dbe7f52852916aa0","kind":"imports","site_id":"site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc","phase":"source","environment":"any","profile_id":"profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9","condition":{"op":"all","conditions":[]},"resolution_status":"resolved","precision":"exact","generated":false,"evidence":[{"kind":"source","extractor":"go-static-worker","extractor_version":"0.2.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}]}'
);
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
INSERT INTO evidence VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'site',
    'site:sha256:e6b683cb3c22063566630ad2875a532fec6be82d688a8817ae1ce29c423589fc',
    0,
    'source',
    'go-static-worker',
    '0.2.0-rc.1',
    'main.go',
    3,
    8,
    3,
    45,
    '{"kind":"source","extractor":"go-static-worker","extractor_version":"0.2.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}'
);
INSERT INTO evidence VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'edge',
    'edge:sha256:0c695eef30a2ae3466742ff5738377269b0eb5974efaa74c1b5ad2dd400f387f',
    0,
    'source',
    'go-static-worker',
    '0.2.0-rc.1',
    'main.go',
    3,
    8,
    3,
    45,
    '{"kind":"source","extractor":"go-static-worker","extractor_version":"0.2.0-rc.1","path":"main.go","start_line":3,"start_column":8,"end_line":3,"end_column":45,"detail":"\"example.com/dependency-snapshot-dep\"","properties":{}}'
);
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
INSERT INTO file_coverage VALUES('legacy-v0.2.0-rc.1-scan','main.go',2,2,0,0,NULL,'go');
CREATE TABLE coverage (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    json TEXT NOT NULL
);
INSERT INTO coverage VALUES(
    'legacy-v0.2.0-rc.1-scan',
    '{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete","semantic-complete"],"reasons":[]}'
);
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
INSERT INTO profile_coverage VALUES(
    'legacy-v0.2.0-rc.1-scan',
    'profile:sha256:15012df3964faf5a7d88a237de0407cfaca331355a0876bd9b869f3f459893e9',
    '{"profiles":1,"files_discovered":1,"files_analyzed":1,"files_skipped":0,"dependency_sites":1,"resolved":1,"candidates":0,"external":0,"unresolved":0,"unsupported_syntax":0,"project_code_executed":false,"completeness":["syntax-complete","semantic-complete"],"reasons":[]}'
);
CREATE INDEX nodes_scan_kind ON nodes(scan_id, kind);
CREATE INDEX nodes_scan_locator ON nodes(scan_id, locator);
CREATE INDEX sites_scan_status ON sites(scan_id, resolution_status);
CREATE INDEX edges_scan_source ON edges(scan_id, source);
CREATE INDEX edges_scan_target ON edges(scan_id, target);
CREATE INDEX edges_scan_kind ON edges(scan_id, kind);
CREATE INDEX edges_scan_site ON edges(scan_id, site_id);
CREATE INDEX evidence_scan_path ON evidence(scan_id, path);
PRAGMA user_version=5;
COMMIT;
