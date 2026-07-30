use crate::config::OutputFormat;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    Scan {
        root: PathBuf,
        strict: bool,
    },
    Query {
        snapshot: String,
        module: String,
    },
    Export {
        snapshot: String,
        format: OutputFormat,
    },
}

#[derive(Clone, Debug, Parser)]
#[command(name = "fixture")]
pub struct Options {
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long, default_value = "depgraph.json")]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Options {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}
