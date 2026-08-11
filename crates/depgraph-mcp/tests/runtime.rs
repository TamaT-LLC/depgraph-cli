use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

use depgraph_core::CancellationToken;
use depgraph_mcp::runtime::{
    AuditErrorCode, AuditLogger, AuditOutcome, AuditPhase, RateLimit, RuntimeClass, RuntimeConfig,
    RuntimeController, RuntimeFailure,
};
use serde_json::Value;

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn default_runtime_limits_match_the_frozen_process_contract() {
    let config = RuntimeConfig::default();
    assert_eq!(config.read_concurrency(), 4);
    assert_eq!(config.submit_concurrency(), 2);
    assert_eq!(config.read_queue_capacity(), 16);
    assert_eq!(config.read_rate(), RateLimit::per_minute(240, 32));
    assert_eq!(config.submit_rate(), RateLimit::per_hour(30, 3));
    let runtime = RuntimeController::new(config).unwrap();
    assert_eq!(
        runtime.deadline(RuntimeClass::Read),
        Duration::from_secs(30)
    );
    assert_eq!(
        runtime.deadline(RuntimeClass::Submit),
        Duration::from_secs(2)
    );
}

#[test]
fn oversized_runtime_capacity_is_rejected_without_panicking() {
    let config = RuntimeConfig::default()
        .with_read_concurrency(tokio::sync::Semaphore::MAX_PERMITS + 1)
        .with_read_queue_capacity(0);
    assert_eq!(
        RuntimeController::new(config).unwrap_err(),
        depgraph_mcp::runtime::RuntimeConfigurationError::InvalidCapacityOrDeadline
    );
}

#[tokio::test]
async fn read_capacity_is_rejected_before_an_extra_operation_starts() {
    let config = RuntimeConfig::default()
        .with_read_concurrency(1)
        .with_read_queue_capacity(0)
        .with_read_rate(RateLimit::per_minute(600, 10));
    let runtime = RuntimeController::new(config).unwrap();
    let release = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));

    let first = tokio::spawn({
        let runtime = runtime.clone();
        let release = Arc::clone(&release);
        let started = Arc::clone(&started);
        async move {
            runtime
                .execute_blocking(RuntimeClass::Read, CancellationToken::new(), move |_| {
                    started.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    Ok::<_, ()>(())
                })
                .await
        }
    });
    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    let second_started = Arc::new(AtomicBool::new(false));
    let failure = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let second_started = Arc::clone(&second_started);
            move |_| {
                second_started.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }
        })
        .await
        .unwrap_err();
    assert_eq!(failure, RuntimeFailure::ResourceExhausted);
    assert!(!second_started.load(Ordering::Acquire));

    release.store(true, Ordering::Release);
    assert_eq!(first.await.unwrap().unwrap(), Ok(()));
}

#[tokio::test]
async fn bounded_read_queue_waits_then_rejects_before_starting_overflow() {
    let config = RuntimeConfig::default()
        .with_read_concurrency(1)
        .with_read_queue_capacity(1)
        .with_read_rate(RateLimit::per_minute(600, 10));
    let runtime = RuntimeController::new(config).unwrap();
    let release = Arc::new(AtomicBool::new(false));
    let first_started = Arc::new(AtomicBool::new(false));
    let first = tokio::spawn({
        let runtime = runtime.clone();
        let release = Arc::clone(&release);
        let first_started = Arc::clone(&first_started);
        async move {
            runtime
                .execute_blocking(RuntimeClass::Read, CancellationToken::new(), move |_| {
                    first_started.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    Ok::<_, ()>(())
                })
                .await
        }
    });
    while !first_started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    let second_started = Arc::new(AtomicBool::new(false));
    let second = tokio::spawn({
        let runtime = runtime.clone();
        let second_started = Arc::clone(&second_started);
        async move {
            runtime
                .execute_blocking(RuntimeClass::Read, CancellationToken::new(), move |_| {
                    second_started.store(true, Ordering::Release);
                    Ok::<_, ()>(())
                })
                .await
        }
    });
    while runtime.admitted_reads() != 2 {
        tokio::task::yield_now().await;
    }
    assert!(!second_started.load(Ordering::Acquire));

    let overflow_started = Arc::new(AtomicBool::new(false));
    let failure = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let overflow_started = Arc::clone(&overflow_started);
            move |_| {
                overflow_started.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }
        })
        .await
        .unwrap_err();
    assert_eq!(failure, RuntimeFailure::ResourceExhausted);
    assert!(!overflow_started.load(Ordering::Acquire));

    release.store(true, Ordering::Release);
    assert_eq!(first.await.unwrap().unwrap(), Ok(()));
    assert_eq!(second.await.unwrap().unwrap(), Ok(()));
}

#[tokio::test]
async fn submit_slot_overflow_is_rejected_before_starting_work() {
    let config = RuntimeConfig::default()
        .with_submit_concurrency(1)
        .with_submit_rate(RateLimit::per_hour(600, 10));
    let runtime = RuntimeController::new(config).unwrap();
    let release = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let first = tokio::spawn({
        let runtime = runtime.clone();
        let release = Arc::clone(&release);
        let started = Arc::clone(&started);
        async move {
            runtime
                .execute_blocking(RuntimeClass::Submit, CancellationToken::new(), move |_| {
                    started.store(true, Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    Ok::<_, ()>(())
                })
                .await
        }
    });
    while !started.load(Ordering::Acquire) || runtime.active_submissions() != 1 {
        tokio::task::yield_now().await;
    }

    let overflow_started = Arc::new(AtomicBool::new(false));
    let failure = runtime
        .execute_blocking(RuntimeClass::Submit, CancellationToken::new(), {
            let overflow_started = Arc::clone(&overflow_started);
            move |_| {
                overflow_started.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }
        })
        .await
        .unwrap_err();
    assert_eq!(failure, RuntimeFailure::ResourceExhausted);
    assert!(!overflow_started.load(Ordering::Acquire));

    release.store(true, Ordering::Release);
    assert_eq!(first.await.unwrap().unwrap(), Ok(()));
}

#[tokio::test]
async fn rate_limit_is_rejected_before_work_starts() {
    let config = RuntimeConfig::default()
        .with_read_concurrency(2)
        .with_read_queue_capacity(0)
        .with_read_rate(RateLimit::per_hour(1, 1));
    let runtime = RuntimeController::new(config).unwrap();
    assert_eq!(
        runtime
            .execute_blocking(RuntimeClass::Read, CancellationToken::new(), |_| {
                Ok::<_, ()>("first")
            })
            .await
            .unwrap(),
        Ok("first")
    );

    let started = Arc::new(AtomicBool::new(false));
    let failure = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let started = Arc::clone(&started);
            move |_| {
                started.store(true, Ordering::Release);
                Ok::<_, ()>("second")
            }
        })
        .await
        .unwrap_err();
    assert_eq!(failure, RuntimeFailure::RateLimited);
    assert!(!started.load(Ordering::Acquire));
}

#[tokio::test]
async fn deadline_cancels_service_work_and_never_publishes_late_success() {
    let runtime = RuntimeController::new(
        RuntimeConfig::default().with_read_deadline(Duration::from_millis(20)),
    )
    .unwrap();
    let observed = Arc::new(AtomicBool::new(false));
    let failure = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let observed = Arc::clone(&observed);
            move |cancellation| {
                while !cancellation.is_cancelled() {
                    std::thread::yield_now();
                }
                observed.store(true, Ordering::Release);
                Ok::<_, ()>("late-success")
            }
        })
        .await
        .unwrap_err();
    assert_eq!(failure, RuntimeFailure::DeadlineExceeded);
    for _ in 0..100 {
        if observed.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(observed.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_cancellation_settles_the_worker_outcome() {
    let runtime = RuntimeController::new(
        RuntimeConfig::default().with_submit_rate(RateLimit::per_hour(600, 10)),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let execution = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        async move {
            runtime
                .execute_mutation_blocking(cancellation, move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok::<_, ()>("committed")
                })
                .await
        }
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    cancellation.cancel();
    release_tx.send(()).unwrap();

    assert_eq!(execution.await.unwrap().unwrap(), Ok("committed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_deadline_settles_the_worker_outcome() {
    let runtime = RuntimeController::new(
        RuntimeConfig::default()
            .with_submit_deadline(Duration::from_millis(20))
            .with_submit_rate(RateLimit::per_hour(600, 10)),
    )
    .unwrap();

    let execution = runtime
        .execute_mutation_blocking(CancellationToken::new(), move |cancellation| {
            while !cancellation.is_cancelled() {
                std::thread::yield_now();
            }
            Ok::<_, ()>("committed")
        })
        .await;

    assert_eq!(execution.unwrap(), Ok("committed"));
}

#[tokio::test]
async fn deadline_keeps_capacity_reserved_until_blocking_work_stops() {
    let runtime = RuntimeController::new(
        RuntimeConfig::default()
            .with_read_concurrency(1)
            .with_read_queue_capacity(0)
            .with_read_deadline(Duration::from_millis(20)),
    )
    .unwrap();
    let release = Arc::new(AtomicBool::new(false));
    let observed_cancellation = Arc::new(AtomicBool::new(false));
    let first = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let release = Arc::clone(&release);
            let observed_cancellation = Arc::clone(&observed_cancellation);
            move |cancellation| {
                while !cancellation.is_cancelled() {
                    std::thread::yield_now();
                }
                observed_cancellation.store(true, Ordering::Release);
                while !release.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Ok::<_, ()>("late-success")
            }
        })
        .await;
    assert_eq!(first.unwrap_err(), RuntimeFailure::DeadlineExceeded);
    while !observed_cancellation.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    assert_eq!(runtime.admitted_reads(), 1);

    let overflow_started = Arc::new(AtomicBool::new(false));
    let failure = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let overflow_started = Arc::clone(&overflow_started);
            move |_| {
                overflow_started.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }
        })
        .await
        .unwrap_err();
    assert_eq!(failure, RuntimeFailure::ResourceExhausted);
    assert!(!overflow_started.load(Ordering::Acquire));

    release.store(true, Ordering::Release);
    for _ in 0..100 {
        if runtime.admitted_reads() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(runtime.admitted_reads(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_keeps_read_capacity_until_the_worker_signals_exit() {
    let runtime = RuntimeController::new(
        RuntimeConfig::default()
            .with_read_concurrency(1)
            .with_read_queue_capacity(0)
            .with_read_rate(RateLimit::per_minute(600, 10)),
    )
    .unwrap();
    let cancellation = CancellationToken::new();
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let (cancelled_tx, cancelled_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let (stopped_tx, stopped_rx) = mpsc::sync_channel(0);
    let first = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        async move {
            runtime
                .execute_blocking(RuntimeClass::Read, cancellation, move |token| {
                    started_tx.send(()).unwrap();
                    while !token.is_cancelled() {
                        std::thread::yield_now();
                    }
                    cancelled_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    stopped_tx.send(()).unwrap();
                    Ok::<_, ()>(())
                })
                .await
        }
    });
    started_rx.recv().unwrap();
    assert_eq!(runtime.admitted_reads(), 1);

    cancellation.cancel();
    assert_eq!(first.await.unwrap().unwrap_err(), RuntimeFailure::Cancelled);
    cancelled_rx.recv().unwrap();
    assert_eq!(runtime.admitted_reads(), 1);
    let second = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), |_| {
            Ok::<_, ()>(())
        })
        .await;
    assert_eq!(second.unwrap_err(), RuntimeFailure::ResourceExhausted);

    release_tx.send(()).unwrap();
    stopped_rx.recv().unwrap();
    while runtime.admitted_reads() != 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(runtime.admitted_reads(), 0);
}

#[tokio::test]
async fn aborting_caller_cancels_worker_and_keeps_capacity_until_worker_exits() {
    let runtime = RuntimeController::new(
        RuntimeConfig::default()
            .with_read_concurrency(1)
            .with_read_queue_capacity(0)
            .with_read_deadline(Duration::from_secs(5)),
    )
    .unwrap();
    let started = Arc::new(AtomicBool::new(false));
    let observed_cancellation = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));

    let task = tokio::spawn({
        let runtime = runtime.clone();
        let started = Arc::clone(&started);
        let observed_cancellation = Arc::clone(&observed_cancellation);
        let release = Arc::clone(&release);
        async move {
            runtime
                .execute_blocking(RuntimeClass::Read, CancellationToken::new(), move |token| {
                    started.store(true, Ordering::Release);
                    while !token.is_cancelled() && !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    observed_cancellation.store(token.is_cancelled(), Ordering::Release);
                    while !release.load(Ordering::Acquire) {
                        std::thread::yield_now();
                    }
                    Ok::<_, ()>("must-not-publish")
                })
                .await
        }
    });
    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    for _ in 0..100 {
        if observed_cancellation.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let overflow_started = Arc::new(AtomicBool::new(false));
    let overflow = runtime
        .execute_blocking(RuntimeClass::Read, CancellationToken::new(), {
            let overflow_started = Arc::clone(&overflow_started);
            move |_| {
                overflow_started.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }
        })
        .await;
    assert_eq!(overflow.unwrap_err(), RuntimeFailure::ResourceExhausted);
    assert!(!overflow_started.load(Ordering::Acquire));

    let observed = observed_cancellation.load(Ordering::Acquire);
    release.store(true, Ordering::Release);
    for _ in 0..100 {
        if runtime.admitted_reads() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        observed,
        "worker did not observe cancellation after caller abort"
    );
    assert_eq!(runtime.admitted_reads(), 0);
}

#[tokio::test]
async fn external_cancellation_reaches_service_work() {
    let runtime = RuntimeController::new(RuntimeConfig::default()).unwrap();
    let cancellation = CancellationToken::new();
    let started = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        let started = Arc::clone(&started);
        let observed = Arc::clone(&observed);
        async move {
            runtime
                .execute_blocking(RuntimeClass::Read, cancellation, move |cancellation| {
                    started.store(true, Ordering::Release);
                    while !cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    observed.store(true, Ordering::Release);
                    Ok::<_, ()>("late-success")
                })
                .await
        }
    });
    while !started.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    cancellation.cancel();
    assert_eq!(task.await.unwrap().unwrap_err(), RuntimeFailure::Cancelled);
    for _ in 0..100 {
        if observed.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(observed.load(Ordering::Acquire));
}

#[tokio::test]
async fn synchronous_work_does_not_occupy_the_tokio_executor() {
    let runtime = RuntimeController::new(RuntimeConfig::default()).unwrap();
    let blocking = tokio::spawn(async move {
        runtime
            .execute_blocking(RuntimeClass::Read, CancellationToken::new(), |_| {
                std::thread::sleep(Duration::from_millis(100));
                Ok::<_, ()>(())
            })
            .await
    });
    tokio::time::timeout(Duration::from_millis(30), async {
        tokio::task::yield_now().await;
    })
    .await
    .expect("Tokio executor was occupied by synchronous work");
    assert_eq!(blocking.await.unwrap().unwrap(), Ok(()));
}

#[test]
fn audit_output_is_allowlisted_and_bounded_per_line_and_request() {
    let buffer = SharedBuffer::default();
    let logger = AuditLogger::with_writer(buffer.clone());
    let mut request = logger.request("agent_nodes_list").unwrap();
    for _ in 0..2_000 {
        request.record(
            AuditPhase::Finished,
            AuditOutcome::Rejected,
            Some(AuditErrorCode::ResourceExhausted),
            Duration::from_millis(7),
        );
    }

    let bytes = buffer.bytes();
    assert!(bytes.len() <= 64 * 1024);
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        assert!(line.len() <= 16 * 1024);
        let value: Value = serde_json::from_slice(line).unwrap();
        let object = value.as_object().unwrap();
        assert!(object.keys().all(|key| matches!(
            key.as_str(),
            "request_id" | "tool" | "phase" | "outcome" | "error_code" | "elapsed_ms"
        )));
        let encoded = String::from_utf8_lossy(line);
        assert!(!encoded.contains("selector"));
        assert!(!encoded.contains("repository_path"));
        assert!(!encoded.contains("result"));
        assert!(!encoded.contains("query"));
    }
}
