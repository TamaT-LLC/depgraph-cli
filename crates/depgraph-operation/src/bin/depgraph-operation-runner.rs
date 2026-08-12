use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, ValueEnum};
use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits,
};
use depgraph_operation::{
    OPERATION_RUNNER_STARTUP_CONTRACT, OperationRunner, RunnerStartupConfig,
    ScanOperationDispatcher,
};

const STARTUP_FAILURE: &str = "depgraph-operation-runner: startup rejected";
const EXECUTION_FAILURE: &str = "depgraph-operation-runner: execution failed";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CapabilityArg {
    Read,
    StoreWrite,
    RepositoryWrite,
    DaemonControl,
    ProjectExec,
}

impl From<CapabilityArg> for DepgraphCapability {
    fn from(value: CapabilityArg) -> Self {
        match value {
            CapabilityArg::Read => Self::Read,
            CapabilityArg::StoreWrite => Self::StoreWrite,
            CapabilityArg::RepositoryWrite => Self::RepositoryWrite,
            CapabilityArg::DaemonControl => Self::DaemonControl,
            CapabilityArg::ProjectExec => Self::ProjectExec,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "depgraph-operation-runner",
    version,
    about = "Detached durable operation journal runner"
)]
struct Args {
    #[arg(long)]
    startup_contract: String,

    #[arg(long)]
    root: PathBuf,

    #[arg(long)]
    store: PathBuf,

    #[arg(long, required = true)]
    capability: Vec<CapabilityArg>,

    #[arg(long)]
    compiler_pack_requirement: Option<PathBuf>,
}

fn startup(args: Args) -> Result<RunnerStartupConfig, ()> {
    if args.startup_contract != OPERATION_RUNNER_STARTUP_CONTRACT {
        return Err(());
    }
    let capabilities = DepgraphCapabilitySet::try_new(
        args.capability
            .iter()
            .copied()
            .map(DepgraphCapability::from),
    )
    .map_err(|_| ())?;
    let config = DepgraphServiceConfig::new(
        args.root,
        args.store,
        capabilities,
        DepgraphServiceLimits::default(),
    )
    .map_err(|_| ())?;
    match args.compiler_pack_requirement {
        Some(path) => RunnerStartupConfig::new_with_compiler_pack_requirement(config, path),
        None => RunnerStartupConfig::new(config),
    }
    .map_err(|_| ())
}

fn main() -> ExitCode {
    let Ok(startup) = startup(Args::parse()) else {
        eprintln!("{STARTUP_FAILURE}");
        return ExitCode::FAILURE;
    };
    let dispatcher = ScanOperationDispatcher::from_startup(&startup);
    match OperationRunner::new(startup, dispatcher).run_until_idle() {
        Ok(_) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("{EXECUTION_FAILURE}");
            ExitCode::FAILURE
        }
    }
}
