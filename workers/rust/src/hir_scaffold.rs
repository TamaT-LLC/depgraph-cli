//! Minimal, inventory-only rust-analyzer integration.
//!
//! This module deliberately exposes only a single-file smoke path. It does not
//! discover a Cargo workspace, read from the repository, load a sysroot, or
//! emit semantic graph events. The confined multi-file project model is added
//! by the follow-up Rust HIR tasks.

use anyhow::{Context, Result, bail};
use ra_ap_hir::{CfgOptions, ChangeWithProcMacros, HirDisplay, Semantics, attach_db};
use ra_ap_ide_db::{
    RootDatabase,
    base_db::{
        CrateGraphBuilder, CrateOrigin, CrateWorkspaceData, Env, FileId, FileSet, SourceRoot,
        VfsPath,
    },
    span::Edition,
};
use ra_ap_syntax::{AstNode, ast};
use ra_ap_vfs::AbsPathBuf;
use std::path::Path;

/// Result of lowering admitted source bytes through the pinned HIR backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HirSmokeResult {
    /// Name resolved through HIR rather than copied from the syntax text.
    pub function_name: String,
    /// HIR-rendered type of the first admitted function.
    pub function_type: String,
}

/// Lower one already-admitted UTF-8 source buffer without exposing a file
/// loader or project model to rust-analyzer.
///
pub fn smoke_inventory_source(source: &[u8], neutral_cwd: &Path) -> Result<HirSmokeResult> {
    let source = std::str::from_utf8(source).context("Rust inventory source is not UTF-8")?;
    let neutral_cwd = neutral_cwd.canonicalize().with_context(|| {
        format!(
            "canonicalize neutral HIR directory {}",
            neutral_cwd.display()
        )
    })?;
    if !neutral_cwd.is_dir() {
        bail!("neutral HIR path is not a directory");
    }
    let neutral_utf8 = neutral_cwd
        .to_str()
        .context("neutral HIR directory is not valid UTF-8")?;
    let proc_macro_cwd = AbsPathBuf::try_from(neutral_utf8)
        .map_err(|_| anyhow::anyhow!("neutral HIR directory is not absolute"))?;

    let file_id = FileId::from_raw(0);
    let mut files = FileSet::default();
    files.insert(file_id, VfsPath::new_virtual_path("/lib.rs".to_owned()));
    let mut crate_graph = CrateGraphBuilder::default();
    crate_graph.add_crate_root(
        file_id,
        Edition::Edition2024,
        None,
        None,
        CfgOptions::default(),
        None,
        Env::default(),
        CrateOrigin::Local {
            repo: None,
            name: None,
        },
        Vec::new(),
        false,
        proc_macro_cwd.into(),
        CrateWorkspaceData {
            target: Err("inventory-only HIR smoke has no target layout".into()),
            toolchain: None,
        }
        .into(),
    );

    let mut change = ChangeWithProcMacros::default();
    change.set_roots(vec![SourceRoot::new_local(files)]);
    change.change_file(file_id, Some(source.to_owned()));
    change.set_crate_graph(crate_graph);
    let mut database = RootDatabase::default();
    database.apply_change(change);

    let semantics = Semantics::new(&database);
    let parsed = semantics.parse_guess_edition(file_id);
    let syntax_function = parsed
        .syntax()
        .descendants()
        .find_map(ast::Fn::cast)
        .context("admitted HIR smoke source has no function")?;
    let function = semantics
        .to_fn_def(&syntax_function)
        .context("pinned rust-analyzer did not lower the admitted function")?;
    let function_name = function.name(&database).as_str().to_owned();
    let display_target = function
        .module(&database)
        .krate(&database)
        .to_display_target(&database);
    let function_type = attach_db(&database, || {
        function
            .ty(&database)
            .display(&database, display_target)
            .to_string()
    });
    Ok(HirSmokeResult {
        function_name,
        function_type,
    })
}

#[cfg(test)]
mod tests {
    use super::smoke_inventory_source;

    #[test]
    fn lowers_only_the_supplied_inventory_bytes() {
        let neutral = tempfile::tempdir().unwrap();
        let marker = neutral.path().join("project-code-executed");
        std::fs::write(
            neutral.path().join("Cargo.toml"),
            "[package]\nname='must-not-load'\nversion='0.0.0'\n",
        )
        .unwrap();
        std::fs::write(
            neutral.path().join("build.rs"),
            format!(
                "fn main() {{ std::fs::write({:?}, b\"executed\").unwrap(); }}",
                marker
            ),
        )
        .unwrap();
        std::fs::write(
            neutral.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel='nightly-do-not-install'\n",
        )
        .unwrap();

        let source = b"struct InventoryOnly { value: u32 }\nfn build() -> InventoryOnly { InventoryOnly { value: 1 } }\n";
        let result = smoke_inventory_source(source, neutral.path()).unwrap();

        assert_eq!(result.function_name, "build");
        assert_eq!(result.function_type, "fn build() -> InventoryOnly");
        assert!(!marker.exists());
    }

    #[test]
    fn rejects_non_utf8_and_sources_without_functions() {
        let neutral = tempfile::tempdir().unwrap();
        assert!(smoke_inventory_source(&[0xff], neutral.path()).is_err());
        assert!(smoke_inventory_source(b"struct NoFunction;", neutral.path()).is_err());
    }
}
