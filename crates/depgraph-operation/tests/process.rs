use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use depgraph_core::{
    DepgraphCapability, DepgraphCapabilitySet, DepgraphServiceConfig, DepgraphServiceLimits,
};
use depgraph_mcp_tools::LogicalRepositoryId;
use depgraph_operation::{
    OPERATION_RUNNER_STARTUP_CONTRACT, OperationJournal, OperationKind, OperationOutcome,
    OperationRunnerLauncher, RunnerStartupConfig, SubmitRequest, UNSUPPORTED_OPERATION_ERROR_JSON,
    operation_journal_path,
};
use rusqlite::Connection;
use serde_json::json;

const HELPER_MODE: &str = "DEPGRAPH_OPERATION_LAUNCHER_HELPER";
const HELPER_ROOT: &str = "DEPGRAPH_OPERATION_HELPER_ROOT";
const HELPER_STORE: &str = "DEPGRAPH_OPERATION_HELPER_STORE";
const HELPER_READY: &str = "DEPGRAPH_OPERATION_HELPER_READY";
const HELPER_LAUNCHED: &str = "DEPGRAPH_OPERATION_HELPER_LAUNCHED";
const STDOUT_SENTINEL: &str = "launcher-server-stdout-intact";
const PROCESS_TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn config(repository: &Path, store: &Path) -> DepgraphServiceConfig {
    DepgraphServiceConfig::new(
        repository,
        store,
        DepgraphCapabilitySet::try_new([DepgraphCapability::Read, DepgraphCapability::StoreWrite])
            .unwrap(),
        DepgraphServiceLimits::default(),
    )
    .unwrap()
}

fn runner_command(repository: &Path, store: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_depgraph-operation-runner"));
    command
        .arg("--startup-contract")
        .arg(OPERATION_RUNNER_STARTUP_CONTRACT)
        .arg("--root")
        .arg(repository)
        .arg("--store")
        .arg(store)
        .arg("--capability")
        .arg("read")
        .arg("--capability")
        .arg("store-write")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.is_file() {
        assert!(Instant::now() < deadline, "marker protocol timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "process exit timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn launcher_server_helper() {
    if std::env::var_os(HELPER_MODE).is_none() {
        return;
    }
    let root = PathBuf::from(std::env::var_os(HELPER_ROOT).unwrap());
    let store = PathBuf::from(std::env::var_os(HELPER_STORE).unwrap());
    let ready = PathBuf::from(std::env::var_os(HELPER_READY).unwrap());
    let launched = PathBuf::from(std::env::var_os(HELPER_LAUNCHED).unwrap());
    let startup = RunnerStartupConfig::new(config(&root, &store)).unwrap();
    let launcher = OperationRunnerLauncher::resolve().unwrap();
    fs::write(&ready, b"ready").unwrap();

    let mut instruction = [0_u8; 1];
    std::io::stdin().read_exact(&mut instruction).unwrap();
    assert_eq!(instruction, [b'L']);
    let runner = launcher.launch(&startup).unwrap();
    fs::write(&launched, runner.process_id().to_string()).unwrap();

    let mut eof = Vec::new();
    std::io::stdin().read_to_end(&mut eof).unwrap();
    assert!(eof.is_empty());
    println!("{STDOUT_SENTINEL}");
}

#[test]
fn accepted_operation_survives_stdin_eof_and_launcher_process_exit() {
    let root = tempfile::tempdir().unwrap();
    let repository_root = root.path().join("repository");
    fs::create_dir(&repository_root).unwrap();
    let store = root.path().join("graph.sqlite");
    let ready = root.path().join("helper.ready");
    let launched = root.path().join("runner.launched");
    let config = config(&repository_root, &store);
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at = now_ms();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"private_payload": "must-never-reach-stdio"}),
                b"detached-launch-acceptance",
                submitted_at + 60_000,
            )
            .unwrap(),
            submitted_at,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let mut helper = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "launcher_server_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER_MODE, "1")
        .env(HELPER_ROOT, &repository_root)
        .env(HELPER_STORE, &store)
        .env(HELPER_READY, &ready)
        .env(HELPER_LAUNCHED, &launched)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_file(&ready, PROCESS_TEST_TIMEOUT);

    let lock = Connection::open(operation_journal_path(&config)).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    helper.stdin.as_mut().unwrap().write_all(b"L").unwrap();
    helper.stdin.as_mut().unwrap().flush().unwrap();
    wait_for_file(&launched, PROCESS_TEST_TIMEOUT);
    let runner_pid: u32 = fs::read_to_string(&launched).unwrap().parse().unwrap();
    assert_ne!(runner_pid, helper.id());
    #[cfg(unix)]
    {
        let runner_group = unsafe { libc::getpgid(runner_pid as i32) };
        assert_eq!(runner_group, runner_pid as i32);
    }

    drop(helper.stdin.take());
    let helper_status = wait_for_exit(&mut helper, PROCESS_TEST_TIMEOUT);
    assert!(helper_status.success());
    let mut helper_stdout = String::new();
    helper
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut helper_stdout)
        .unwrap();
    let mut helper_stderr = String::new();
    helper
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut helper_stderr)
        .unwrap();
    assert!(helper_stdout.contains(STDOUT_SENTINEL));
    assert!(!helper_stdout.contains("must-never-reach-stdio"));
    assert!(!helper_stderr.contains("must-never-reach-stdio"));

    lock.execute_batch("COMMIT").unwrap();
    let deadline = Instant::now() + PROCESS_TEST_TIMEOUT;
    loop {
        let journal = OperationJournal::open(&config).unwrap();
        match journal.result(&repository, &operation_id, now_ms()) {
            Ok(OperationOutcome::Failed(error)) => {
                assert_eq!(error.as_str(), UNSUPPORTED_OPERATION_ERROR_JSON);
                break;
            }
            Err(depgraph_operation::JournalError::OperationNotReady) => {}
            other => panic!("unexpected detached runner state: {other:?}"),
        }
        assert!(Instant::now() < deadline, "detached runner did not finish");
        thread::sleep(Duration::from_millis(10));
    }
    #[cfg(unix)]
    {
        let cleanup_deadline = Instant::now() + PROCESS_TEST_TIMEOUT;
        while unsafe { libc::kill(runner_pid as i32, 0) } == 0 {
            assert!(
                Instant::now() < cleanup_deadline,
                "detached runner process was not reaped after terminal persistence"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}

#[test]
fn runner_rejects_unknown_startup_contract_without_echoing_config() {
    let root = tempfile::tempdir().unwrap();
    let repository = root.path().join("private-repository-name");
    fs::create_dir(&repository).unwrap();
    let store = root.path().join("private-store-name.sqlite");
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-operation-runner"))
        .arg("--startup-contract")
        .arg("unknown-contract")
        .arg("--root")
        .arg(&repository)
        .arg("--store")
        .arg(&store)
        .arg("--capability")
        .arg("read")
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "depgraph-operation-runner: startup rejected\n"
    );
    assert!(!store.exists());
}

#[test]
fn runner_reports_the_packaged_version_handshake() {
    let output = Command::new(env!("CARGO_BIN_EXE_depgraph-operation-runner"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("depgraph-operation-runner {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn two_runner_processes_claim_one_record_only_once() {
    let root = tempfile::tempdir().unwrap();
    let repository_root = root.path().join("repository");
    fs::create_dir(&repository_root).unwrap();
    let store = root.path().join("graph.sqlite");
    let config = config(&repository_root, &store);
    let repository = LogicalRepositoryId::parse(config.logical_repository_id()).unwrap();
    let submitted_at = now_ms();
    let mut journal = OperationJournal::open(&config).unwrap();
    let operation_id = journal
        .submit(
            &SubmitRequest::new(
                &config,
                OperationKind::ScanSubmit,
                &json!({"claim": "once"}),
                b"two-runner-process-claim",
                submitted_at + 60_000,
            )
            .unwrap(),
            submitted_at,
        )
        .unwrap()
        .operation_id()
        .clone();
    drop(journal);

    let lock = Connection::open(operation_journal_path(&config)).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let first = runner_command(&repository_root, &store).spawn().unwrap();
    let second = runner_command(&repository_root, &store).spawn().unwrap();
    lock.execute_batch("COMMIT").unwrap();

    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert!(first.status.success());
    assert!(second.status.success());
    assert!(first.stdout.is_empty() && first.stderr.is_empty());
    assert!(second.stdout.is_empty() && second.stderr.is_empty());

    let journal = OperationJournal::open(&config).unwrap();
    let handoff = journal
        .runner_handoff(&repository, &operation_id, now_ms())
        .unwrap();
    assert!(handoff.claimed_at_ms().is_some());
    assert!(handoff.completed_at_ms().is_some());
    match journal
        .result(&repository, &operation_id, now_ms())
        .unwrap()
    {
        OperationOutcome::Failed(error) => {
            assert_eq!(error.as_str(), UNSUPPORTED_OPERATION_ERROR_JSON);
        }
        other => panic!("unexpected two-runner outcome: {other:?}"),
    }
}
