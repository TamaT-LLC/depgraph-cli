use super::*;

fn write(root: &Path, path: &str, text: &str) -> Result<()> {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap())?;
    fs::write(target, text)?;
    Ok(())
}

fn plan(root: &Path) -> Result<AnalysisPlan> {
    discover_analysis_plan(
        root,
        &Config::default(),
        &AnalysisPlanInput::new(["profile:test"], "static-import-regression"),
    )
}

fn executable<'a>(plan: &'a AnalysisPlan, root: &str) -> &'a AnalysisUnit {
    plan.units
        .iter()
        .find(|unit| unit.is_executable() && unit.unit_root == root)
        .unwrap()
}

#[test]
fn go_source_imports_use_the_longest_module_namespace_and_own_checkout() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for (directory, module) in [
        (".", "example.test/app"),
        ("tools", "example.test/app/tools"),
        ("copy", "example.test/app"),
    ] {
        write(
            temp.path(),
            &format!("{directory}/go.mod"),
            &format!("module {module}\n\ngo 1.26\n"),
        )?;
        write(
            temp.path(),
            &format!("{directory}/main.go"),
            &format!(
                "package main\nimport \"{module}/internal/lib\"\nfunc main() {{ lib.Run() }}\n"
            ),
        )?;
        write(
            temp.path(),
            &format!("{directory}/internal/lib/lib.go"),
            "package lib\nfunc Run() {}\n",
        )?;
    }
    let plan = plan(temp.path())?;
    for directory in [".", "tools", "copy"] {
        let unit = executable(&plan, directory);
        assert!(
            !unit.unknown_dependencies,
            "{directory}: {:?}",
            unit.dependency_references
        );
        let reference = unit
            .dependency_references
            .iter()
            .find(|reference| reference.kind == AnalysisDependencyKind::SourceImport)
            .unwrap();
        let target = plan
            .unit(reference.target_unit_id.as_deref().unwrap())
            .unwrap();
        assert_eq!(
            target.unit_root,
            join_relative(directory, "internal/lib").unwrap()
        );
    }
    Ok(())
}

#[test]
fn web_import_planning_keeps_real_alias_and_type_dependencies_without_documentation_examples()
-> Result<()> {
    let temp = tempfile::tempdir()?;
    write(
        temp.path(),
        "package.json",
        r#"{"name":"workspace","workspaces":["apps/*","packages/*"]}"#,
    )?;
    write(
        temp.path(),
        "apps/web/package.json",
        r#"{"name":"web","devDependencies":{"@types/geojson":"1.0.0"}}"#,
    )?;
    write(
        temp.path(),
        "packages/shared/package.json",
        r#"{"name":"@example/shared"}"#,
    )?;
    write(
        temp.path(),
        "packages/shared/src/value.ts",
        "export const value = 1;",
    )?;
    write(
        temp.path(),
        "settings/base.json",
        "{ // JSONC is configuration data, not code.\n\"compilerOptions\": {\"target\": \"ESNext\",},\n}",
    )?;
    write(
        temp.path(),
        "apps/web/tsconfig.json",
        r#"{
        "extends":"../../settings/base.json",
        "compilerOptions":{"paths":{"@/*":["./src/*"],"@shared/*":["../../packages/shared/src/*"]}}
    }"#,
    )?;
    write(
        temp.path(),
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\npackages:\n  '@svgr/core@8.1.0':\n    resolution: {integrity: test}\n  '@types/estree@1.0.0': {}\nsnapshots:\n  '@svgr/core@8.1.0': {}\n",
    )?;
    write(
        temp.path(),
        "apps/web/src/local.ts",
        "export const local = 1;",
    )?;
    write(
        temp.path(),
        "apps/web/src/main.ts",
        r#"
        import { value }
            from '@shared/value';
        import { local } from '@/local';
        import { Feature } from 'geojson';
        import { readFile } from 'fs/promises';
        /** @type {import('@svgr/core').Config} */
        const config = {};
        const example = "import { missing } from 'quoted-example'";
        // import { missing } from 'comment-example';
        dayjs.from(value).format('YYYY/MM/DD');
    "#,
    )?;
    write(
        temp.path(),
        "apps/web/README.md",
        "```ts\nimport example from 'documentation-example';\n```\n",
    )?;
    let before = plan(temp.path())?;
    let app = executable(&before, "apps/web");
    assert!(!app.unknown_dependencies, "{:?}", app.dependency_references);
    let sources = app
        .dependency_references
        .iter()
        .filter(|reference| reference.kind == AnalysisDependencyKind::SourceImport)
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 5);
    assert!(
        sources
            .iter()
            .any(|reference| reference.specifier == "@shared/value"
                && reference.target_unit_id.as_deref()
                    == Some(executable(&before, "packages/shared").id.as_str()))
    );
    assert!(
        sources
            .iter()
            .any(|reference| reference.specifier == "@/local"
                && reference.target_unit_id.as_deref() == Some(app.id.as_str()))
    );
    assert!(
        sources
            .iter()
            .filter(|reference| ["geojson", "fs/promises", "@svgr/core"]
                .contains(&reference.specifier.as_str()))
            .all(|reference| reference.resolution == AnalysisDependencyResolution::External)
    );
    assert!(
        app.source_paths.contains(&"apps/web/README.md".to_owned()),
        "documentation remains in the owned input"
    );
    assert!(
        app.config_paths.contains(&"settings/base.json".to_owned()),
        "inherited config must be fingerprinted"
    );
    write(
        temp.path(),
        "settings/base.json",
        r#"{"compilerOptions":{"target":"ES2023"}}"#,
    )?;
    let after = plan(temp.path())?;
    assert_ne!(
        app.input_fingerprint,
        executable(&after, "apps/web").input_fingerprint
    );
    Ok(())
}

#[test]
fn alias_inheritance_preserves_definition_origin_and_does_not_hide_missing_targets() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write(
        temp.path(),
        "package.json",
        r#"{"name":"workspace","workspaces":["apps/*","packages/*"]}"#,
    )?;
    write(
        temp.path(),
        "apps/web/package.json",
        r#"{"name":"web","devDependencies":{"@example/config":"workspace:*"}}"#,
    )?;
    write(
        temp.path(),
        "packages/config/package.json",
        r#"{"name":"@example/config"}"#,
    )?;
    write(
        temp.path(),
        "packages/shared/package.json",
        r#"{"name":"@example/shared"}"#,
    )?;
    write(
        temp.path(),
        "packages/shared/value.ts",
        "export const value = 1;",
    )?;
    write(
        temp.path(),
        "packages/config/base.json",
        r#"{"compilerOptions":{"paths":{"@shared/*":["../shared/*"]}}}"#,
    )?;
    write(
        temp.path(),
        "apps/web/tsconfig.json",
        r#"{"extends":"@example/config/base.json"}"#,
    )?;
    write(
        temp.path(),
        "apps/web/main.ts",
        "import { value } from '@shared/value';",
    )?;
    let inherited = plan(temp.path())?;
    assert!(!executable(&inherited, "apps/web").unknown_dependencies);
    assert!(
        executable(&inherited, "apps/web")
            .config_paths
            .contains(&"packages/config/base.json".to_owned())
    );
    write(
        temp.path(),
        "apps/web/main.ts",
        "import { value } from '@shared/missing';\nimport missing from 'fs/not-a-builtin';",
    )?;
    let missing = plan(temp.path())?;
    assert!(executable(&missing, "apps/web").unknown_dependencies);
    assert_eq!(
        executable(&missing, "apps/web")
            .dependency_references
            .iter()
            .filter(|reference| reference.resolution == AnalysisDependencyResolution::Unknown)
            .count(),
        2
    );
    write(
        temp.path(),
        "apps/web/main.ts",
        "import { value } from '@shared/value';",
    )?;
    write(
        temp.path(),
        "apps/web/tsconfig.json",
        r#"{"extends":"@example/config/base.json","compilerOptions":{"paths":{}}}"#,
    )?;
    assert!(
        executable(&plan(temp.path())?, "apps/web").unknown_dependencies,
        "an explicit empty paths map must override inherited aliases"
    );
    Ok(())
}

#[test]
fn cyclic_configs_and_local_lock_entries_do_not_certify_external_imports() -> Result<()> {
    let temp = tempfile::tempdir()?;
    write(temp.path(), "package.json", r#"{"name":"app"}"#)?;
    write(
        temp.path(),
        "tsconfig.json",
        r#"{"extends":"./base.json","compilerOptions":{"paths":{"@/*":["src/*"]}}}"#,
    )?;
    write(temp.path(), "base.json", r#"{"extends":"./tsconfig.json"}"#)?;
    write(
        temp.path(),
        "pnpm-lock.yaml",
        "packages:\n  'local-only@file:../outside':\n    resolution: {}\n",
    )?;
    write(temp.path(), "src/local.ts", "export const local = 1;")?;
    write(
        temp.path(),
        "main.ts",
        "import { local } from '@/local';\nimport value from 'local-only';",
    )?;
    let plan = plan(temp.path())?;
    let app = executable(&plan, ".");
    assert!(app.unknown_dependencies);
    assert_eq!(
        app.dependency_references
            .iter()
            .filter(|reference| reference.resolution == AnalysisDependencyResolution::Unknown)
            .count(),
        2
    );
    Ok(())
}
