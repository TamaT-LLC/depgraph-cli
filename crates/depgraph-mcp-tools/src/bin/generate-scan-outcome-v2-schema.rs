use std::{env, ffi::OsString, fs, io::Write as _, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<(), String> {
    let output = arguments.next().map(PathBuf::from);
    if arguments.next().is_some() {
        return Err("usage: generate-scan-outcome-v2-schema [OUTPUT]".to_owned());
    }

    let bytes = depgraph_mcp_tools::canonical_json_bytes(
        &depgraph_mcp_tools::agent_scan_outcome_v2_schema(),
    )
    .map_err(|error| format!("failed to serialize scan outcome schema: {error}"))?;
    if let Some(output) = output {
        fs::write(&output, bytes)
            .map_err(|error| format!("failed to write {}: {error}", output.display()))
    } else {
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(|error| format!("failed to write schema to stdout: {error}"))
    }
}
