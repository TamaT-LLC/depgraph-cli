use depgraph_core::DepgraphCapability;
use serde_json::json;

use crate::catalog::CapabilityProfile;

pub const AGENT_HOST_CONFIG_CONTRACT_VERSION: &str = "depgraph-agent-host-config-v1";
pub const MCP_SDK_NAME: &str = "rmcp";
pub const MCP_SDK_VERSION: &str = "3.1.0";
pub const MCP_PROTOCOL_REVISION: &str = "2026-07-28";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentHostFormat {
    Codex,
    ClaudeDesktop,
    VsCode,
}

impl AgentHostFormat {
    pub const ALL: [Self; 3] = [Self::Codex, Self::ClaudeDesktop, Self::VsCode];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeDesktop => "claude-desktop",
            Self::VsCode => "vscode",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentHostCapabilityProfile {
    Read,
    StoreWrite,
    RepositoryWrite,
    DaemonControl,
    ProjectExec,
    Full,
}

impl AgentHostCapabilityProfile {
    pub const ALL: [Self; 6] = [
        Self::Read,
        Self::StoreWrite,
        Self::RepositoryWrite,
        Self::DaemonControl,
        Self::ProjectExec,
        Self::Full,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::StoreWrite => "store-write",
            Self::RepositoryWrite => "repository-write",
            Self::DaemonControl => "daemon-control",
            Self::ProjectExec => "project-exec",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub const fn capabilities(self) -> &'static [DepgraphCapability] {
        match self {
            Self::Read => CapabilityProfile::Read.required_capabilities(),
            Self::StoreWrite => CapabilityProfile::StoreWrite.required_capabilities(),
            Self::RepositoryWrite => CapabilityProfile::RepositoryWrite.required_capabilities(),
            Self::DaemonControl => CapabilityProfile::DaemonControl.required_capabilities(),
            Self::ProjectExec => CapabilityProfile::ProjectExec.required_capabilities(),
            Self::Full => &[
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::RepositoryWrite,
                DepgraphCapability::DaemonControl,
                DepgraphCapability::ProjectExec,
            ],
        }
    }

    #[must_use]
    pub const fn is_privileged(self) -> bool {
        !matches!(self, Self::Read)
    }

    #[must_use]
    pub const fn permits_project_execution(self) -> bool {
        matches!(self, Self::ProjectExec | Self::Full)
    }

    #[must_use]
    pub const fn effect_summary(self) -> &'static str {
        match self {
            Self::Read => {
                "read-only graph, context, validation, status, and durable-operation recovery"
            }
            Self::StoreWrite => {
                "read plus Store/journal mutation for safe scans and validated runtime imports"
            }
            Self::RepositoryWrite => {
                "read plus confined repository initialization/file export and durable journal state"
            }
            Self::DaemonControl => {
                "read plus Store/journal mutation and persistent watcher daemon lifecycle"
            }
            Self::ProjectExec => {
                "read plus Store/journal mutation and supervised execution of project code"
            }
            Self::Full => "all read, Store, repository, daemon, and project-code execution effects",
        }
    }
}

#[must_use]
pub fn agent_host_launch_arguments(
    profile: AgentHostCapabilityProfile,
    root: &str,
    store: &str,
    compiler_pack_requirement: &str,
) -> Vec<String> {
    let mut arguments = vec![
        "--root".to_owned(),
        root.to_owned(),
        "--store".to_owned(),
        store.to_owned(),
    ];
    for capability in profile.capabilities() {
        arguments.push("--capability".to_owned());
        arguments.push(agent_host_capability_name(*capability).to_owned());
    }
    arguments.extend([
        "--compiler-pack-requirement".to_owned(),
        compiler_pack_requirement.to_owned(),
        "--log-level".to_owned(),
        "warn".to_owned(),
    ]);
    arguments
}

pub fn render_agent_host_configuration(
    format: AgentHostFormat,
    profile: AgentHostCapabilityProfile,
    executable: &str,
    root: &str,
    store: &str,
    compiler_pack_requirement: &str,
) -> Result<String, String> {
    if [executable, root, store, compiler_pack_requirement]
        .iter()
        .any(|value| value.is_empty())
    {
        return Err("Agent host configuration paths must not be empty".to_owned());
    }
    let arguments = agent_host_launch_arguments(profile, root, store, compiler_pack_requirement);
    match format {
        AgentHostFormat::ClaudeDesktop => serde_json::to_string_pretty(&json!({
            "mcpServers": {
                "depgraph": {
                    "command": executable,
                    "args": arguments
                }
            }
        }))
        .map_err(|error| error.to_string()),
        AgentHostFormat::VsCode => serde_json::to_string_pretty(&json!({
            "servers": {
                "depgraph": {
                    "type": "stdio",
                    "command": executable,
                    "args": arguments
                }
            }
        }))
        .map_err(|error| error.to_string()),
        AgentHostFormat::Codex => render_codex_configuration(profile, executable, &arguments),
    }
}

fn render_codex_configuration(
    profile: AgentHostCapabilityProfile,
    executable: &str,
    arguments: &[String],
) -> Result<String, String> {
    let arguments = arguments
        .iter()
        .map(|argument| toml_string(argument))
        .collect::<Result<Vec<_>, _>>()?
        .join(", ");
    let approval_mode = if profile.is_privileged() {
        "prompt"
    } else {
        "approve"
    };
    Ok(format!(
        "[mcp_servers.depgraph]\ncommand = {}\nargs = [{}]\nenabled = true\nrequired = true\ndefault_tools_approval_mode = {approval_mode:?}",
        toml_string(executable)?,
        arguments
    ))
}

fn toml_string(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

#[must_use]
pub const fn agent_host_capability_name(capability: DepgraphCapability) -> &'static str {
    match capability {
        DepgraphCapability::Read => "read",
        DepgraphCapability::StoreWrite => "store-write",
        DepgraphCapability::RepositoryWrite => "repository-write",
        DepgraphCapability::DaemonControl => "daemon-control",
        DepgraphCapability::ProjectExec => "project-exec",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXECUTABLE: &str = "/release/bin/depgraph-mcp";
    const ROOT: &str = "/work/repository";
    const STORE: &str = "/private/depgraph.sqlite";
    const REQUIREMENT: &str = "/release/compiler-pack.requirement.json";

    #[test]
    fn default_profile_is_the_exact_read_only_closure() {
        assert_eq!(
            AgentHostCapabilityProfile::Read.capabilities(),
            &[DepgraphCapability::Read]
        );
        assert!(!AgentHostCapabilityProfile::Read.is_privileged());
        assert!(!AgentHostCapabilityProfile::Read.permits_project_execution());
        let arguments =
            agent_host_launch_arguments(AgentHostCapabilityProfile::Read, ROOT, STORE, REQUIREMENT);
        assert_eq!(
            arguments,
            [
                "--root",
                ROOT,
                "--store",
                STORE,
                "--capability",
                "read",
                "--compiler-pack-requirement",
                REQUIREMENT,
                "--log-level",
                "warn",
            ]
        );
    }

    #[test]
    fn all_host_formats_render_the_same_launch_tuple() {
        for format in AgentHostFormat::ALL {
            let rendered = render_agent_host_configuration(
                format,
                AgentHostCapabilityProfile::Read,
                EXECUTABLE,
                ROOT,
                STORE,
                REQUIREMENT,
            )
            .unwrap();
            for value in [EXECUTABLE, ROOT, STORE, REQUIREMENT] {
                assert!(
                    rendered.contains(value),
                    "{} omitted {value}",
                    format.as_str()
                );
            }
            assert!(rendered.contains("read"));
            assert!(!rendered.contains("store-write"));
            assert!(!rendered.contains("project-exec"));
        }
    }

    #[test]
    fn privileged_profiles_have_exact_dependency_closures_and_prompt_in_codex() {
        assert_eq!(
            AgentHostCapabilityProfile::Full.capabilities(),
            &[
                DepgraphCapability::Read,
                DepgraphCapability::StoreWrite,
                DepgraphCapability::RepositoryWrite,
                DepgraphCapability::DaemonControl,
                DepgraphCapability::ProjectExec,
            ]
        );
        for profile in AgentHostCapabilityProfile::ALL
            .into_iter()
            .filter(|profile| profile.is_privileged())
        {
            let rendered = render_agent_host_configuration(
                AgentHostFormat::Codex,
                profile,
                EXECUTABLE,
                ROOT,
                STORE,
                REQUIREMENT,
            )
            .unwrap();
            assert!(rendered.contains("default_tools_approval_mode = \"prompt\""));
        }
    }
}
