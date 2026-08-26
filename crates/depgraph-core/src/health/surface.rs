use depgraph_store::NodeRecord;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceRole {
    EntryPoint,
    PublicSurface,
    DynamicLoading,
    Generated,
    Internal,
    InsufficientEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceClassification {
    pub role: SurfaceRole,
    pub language: Option<String>,
    pub reasons: Vec<String>,
}

#[must_use]
pub fn classify_surface(node: &NodeRecord) -> SurfaceClassification {
    let language = string_property(node, "language");
    let mut reasons = Vec::new();

    if bool_property(node, "generated")
        || node.locator.contains("generated")
        || path_of(node).is_some_and(|path| {
            path.contains("/generated/") || path.contains(".generated.") || path.ends_with(".g.rs")
        })
    {
        reasons.push("generated artifact marker".to_owned());
        return SurfaceClassification {
            role: SurfaceRole::Generated,
            language,
            reasons,
        };
    }

    if is_dynamic_loading(node) {
        reasons.push("dynamic loading marker".to_owned());
        return SurfaceClassification {
            role: SurfaceRole::DynamicLoading,
            language,
            reasons,
        };
    }

    if is_entry_point(node, &mut reasons) {
        return SurfaceClassification {
            role: SurfaceRole::EntryPoint,
            language,
            reasons,
        };
    }

    if is_public_surface(node, language.as_deref(), &mut reasons) {
        return SurfaceClassification {
            role: SurfaceRole::PublicSurface,
            language,
            reasons,
        };
    }

    if needs_visibility_evidence(node, language.as_deref()) {
        reasons.push("visibility is not recorded on the node".to_owned());
        return SurfaceClassification {
            role: SurfaceRole::InsufficientEvidence,
            language,
            reasons,
        };
    }

    reasons.push("no public or entry marker".to_owned());
    SurfaceClassification {
        role: SurfaceRole::Internal,
        language,
        reasons,
    }
}

fn is_entry_point(node: &NodeRecord, reasons: &mut Vec<String>) -> bool {
    if node.kind == "route"
        || node.kind == "server_function"
        || node.kind == "middleware"
        || matches!(
            string_property(node, "target_kind").as_deref(),
            Some("bin" | "test" | "bench" | "example")
        )
        || matches!(
            string_property(node, "variant").as_deref(),
            Some("main" | "test" | "xtest")
        )
    {
        reasons.push(format!("node kind {} is an entry surface", node.kind));
        return true;
    }
    if let Some(path) = path_of(node)
        && (path == "src/lib.rs"
            || matches!(
                path.as_str(),
                "main.rs" | "main.go" | "main.ts" | "main.js" | "index.ts" | "index.js"
            )
            || path.ends_with("/src/lib.rs")
            || path.ends_with("/main.rs")
            || path.ends_with("/main.go")
            || path.ends_with("/main.ts")
            || path.ends_with("/main.js")
            || path.ends_with("/index.ts")
            || path.ends_with("/index.js")
            || path.contains("/bin/")
            || path.contains("/cmd/"))
    {
        reasons.push(format!("path {path} is an entry-point convention"));
        return true;
    }
    false
}

fn is_public_surface(node: &NodeRecord, language: Option<&str>, reasons: &mut Vec<String>) -> bool {
    if bool_property(node, "exported")
        || bool_property(node, "public")
        || matches!(
            string_property(node, "visibility").as_deref(),
            Some("pub" | "public" | "exported")
        )
    {
        reasons.push("exported/public property".to_owned());
        return true;
    }
    if node.kind == "route" || node.kind == "component" {
        reasons.push("framework public surface".to_owned());
        return true;
    }
    if language == Some("go") && exported_go_ident(node) {
        reasons.push("Go exported identifier".to_owned());
        return true;
    }
    if matches!(language, Some("typescript" | "javascript" | "ts" | "js"))
        && (node.kind == "symbol" || node.kind == "type")
        && bool_property(node, "exported")
    {
        reasons.push("TypeScript/JavaScript export".to_owned());
        return true;
    }
    false
}

fn is_dynamic_loading(node: &NodeRecord) -> bool {
    bool_property(node, "dynamic")
        || matches!(
            string_property(node, "load_kind").as_deref(),
            Some("dynamic" | "lazy" | "import()")
        )
        || node.kind == "unknown_target"
            && string_property(node, "reason")
                .is_some_and(|reason| reason.contains("dynamic") || reason.contains("plugin"))
}

fn needs_visibility_evidence(node: &NodeRecord, language: Option<&str>) -> bool {
    matches!(node.kind.as_str(), "symbol" | "type")
        && matches!(language, Some("rust") | None)
        && !bool_property(node, "exported")
        && !bool_property(node, "public")
        && string_property(node, "visibility").is_none()
}

fn exported_go_ident(node: &NodeRecord) -> bool {
    let name = string_property(node, "name")
        .or_else(|| string_property(node, "ident"))
        .unwrap_or_else(|| node.display_name.clone());
    name.chars()
        .next()
        .is_some_and(|first| first.is_ascii_uppercase())
}

fn path_of(node: &NodeRecord) -> Option<String> {
    string_property(node, "path")
        .or_else(|| string_property(node, "source_path"))
        .or_else(|| string_property(node, "src_path"))
        .or_else(|| string_property(node, "relative_path"))
}

fn string_property(node: &NodeRecord, key: &str) -> Option<String> {
    node.properties
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn bool_property(node: &NodeRecord, key: &str) -> bool {
    node.properties
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn node(kind: &str, language: &str, properties: Value) -> NodeRecord {
        NodeRecord {
            id: format!("{kind}:fixture"),
            kind: kind.to_owned(),
            locator: format!("repo://{kind}"),
            display_name: "Fixture".to_owned(),
            properties: {
                let mut map = properties.as_object().cloned().unwrap_or_default();
                map.entry("language".to_owned())
                    .or_insert_with(|| json!(language));
                Value::Object(map)
            },
        }
    }

    #[test]
    fn issue_423_classifies_rust_go_and_typescript_entry_and_public_surfaces() {
        let rust_bin = node(
            "build_unit",
            "rust",
            json!({"target_kind": "bin", "src_path": "src/main.rs"}),
        );
        assert_eq!(classify_surface(&rust_bin).role, SurfaceRole::EntryPoint);

        let go_export = node("symbol", "go", json!({"name": "Exported"}));
        assert_eq!(
            classify_surface(&go_export).role,
            SurfaceRole::PublicSurface
        );

        let ts_route = node("route", "typescript", json!({"path": "app/page.tsx"}));
        assert_eq!(classify_surface(&ts_route).role, SurfaceRole::EntryPoint);

        let generated = node(
            "file",
            "rust",
            json!({"generated": true, "path": "src/g.rs"}),
        );
        assert_eq!(classify_surface(&generated).role, SurfaceRole::Generated);
    }

    #[test]
    fn issue_423_unclassified_rust_symbol_is_an_evidence_blocker() {
        let rust_symbol = node("symbol", "rust", json!({"name": "helper"}));
        let classified = classify_surface(&rust_symbol);
        assert_eq!(classified.role, SurfaceRole::InsufficientEvidence);
        assert!(
            classified
                .reasons
                .iter()
                .any(|reason| reason.contains("visibility"))
        );
    }

    #[test]
    fn issue_423_dynamic_loading_entry_points_and_internal_files_are_distinct() {
        let dynamic = node(
            "file",
            "javascript",
            json!({"load_kind": "import()", "path": "src/plugin.js"}),
        );
        assert_eq!(classify_surface(&dynamic).role, SurfaceRole::DynamicLoading);

        let crate_root = node("file", "rust", json!({"path": "crates/core/src/lib.rs"}));
        assert_eq!(classify_surface(&crate_root).role, SurfaceRole::EntryPoint);

        let internal = node("file", "rust", json!({"path": "src/helper.rs"}));
        assert_eq!(classify_surface(&internal).role, SurfaceRole::Internal);
    }
}
