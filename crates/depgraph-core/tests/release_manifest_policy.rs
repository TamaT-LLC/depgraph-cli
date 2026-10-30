//! The process-wide release manifest requirement that the packaged `depgraph`
//! binary sets at the start of `main`.
//!
//! The requirement cannot be cleared once set, so this file owns its process:
//! it holds a single test that observes the lookup before and after setting it.

use depgraph_core::worker::{
    AdapterKind, locate_worker, release_manifest_required, require_release_manifest,
};

const MISSING_MANIFEST: &str = "packaged installation is missing release-manifest.json";

#[test]
fn required_release_manifest_is_one_way_and_stops_worker_lookup() {
    // The test executable lives in target/<profile>/deps, which has no release
    // manifest and is not a packaged bin/ + libexec/ layout.
    assert!(!release_manifest_required());
    let before = locate_worker(AdapterKind::Go)
        .err()
        .map(|error| format!("{error:#}"))
        .unwrap_or_default();
    assert!(!before.contains(MISSING_MANIFEST), "{before}");

    require_release_manifest();
    assert!(release_manifest_required());
    let error = locate_worker(AdapterKind::Go)
        .expect_err("a required release manifest must stop the worker lookup");
    assert!(format!("{error:#}").contains(MISSING_MANIFEST), "{error:#}");

    // Setting it again keeps it set; nothing turns it off.
    require_release_manifest();
    assert!(release_manifest_required());
}
