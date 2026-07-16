//! Validates a worker stream from stdin against the typed protocol contract.

use depgraph_protocol::{validate_ndjson, validate_safe_ndjson};
use std::io::{self, BufReader};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let safe_scan = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [argument] if argument == "--safe" => true,
        _ => return Err("usage: validate_ndjson [--safe]".into()),
    };
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    let validated = if safe_scan {
        validate_safe_ndjson(reader)?
    } else {
        validate_ndjson(reader)?
    };
    eprintln!(
        "validated {} events, {} nodes, {} edges, {} dependency sites",
        validated.events.len(),
        validated.nodes.len(),
        validated.edges.len(),
        validated.sites.len()
    );
    Ok(())
}
