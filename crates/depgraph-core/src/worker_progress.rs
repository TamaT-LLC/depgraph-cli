//! Progress is an advancing work counter or a new completed phase, never a
//! repeated log line or a heartbeat. It extends a unit's inactivity deadline.

use std::collections::{BTreeMap, BTreeSet};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::watch,
};

const MAX_PROGRESS_LINE_BYTES: usize = 4_096;
const MAX_PROGRESS_PHASES: usize = 64;

#[derive(Default)]
struct ProgressTracker {
    counters: BTreeMap<String, u64>,
    completed: BTreeSet<String>,
}

impl ProgressTracker {
    fn observe(&mut self, line: &[u8]) -> bool {
        let Ok(line) = std::str::from_utf8(line) else {
            return false;
        };
        let Some(fields) = line.strip_prefix("depgraph-progress ") else {
            return false;
        };
        let fields = fields
            .split_whitespace()
            .filter_map(|field| field.split_once('='))
            .collect::<BTreeMap<_, _>>();
        let Some(phase) = fields.get("phase") else {
            return false;
        };
        if phase.is_empty()
            || phase.len() > 64
            || !phase
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return false;
        }
        let Some(status) = fields.get("status") else {
            return false;
        };
        if !matches!(*status, "progress" | "completed") {
            return false;
        }
        let counter = ["items", "files", "source_files", "completed_units"]
            .into_iter()
            .filter_map(|name| fields.get(name)?.parse::<u64>().ok())
            .max();
        let advanced = if let Some(counter) = counter {
            let previous = self.counters.get(*phase).copied().unwrap_or(0);
            if counter > previous
                && (self.counters.contains_key(*phase) || self.counters.len() < MAX_PROGRESS_PHASES)
            {
                self.counters.insert((*phase).to_owned(), counter);
                true
            } else {
                false
            }
        } else {
            false
        };
        let completed = *status == "completed"
            && self.completed.len() < MAX_PROGRESS_PHASES
            && self.completed.insert((*phase).to_owned());
        advanced || completed
    }
}

pub(crate) async fn read_progress_stderr(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
    progress: watch::Sender<u64>,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut line = Vec::new();
    let mut oversized_line = false;
    let mut truncated = false;
    let mut tracker = ProgressTracker::default();
    let mut generation = 0_u64;
    let mut buffer = [0_u8; 8_192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let keep = count.min(limit.saturating_sub(retained.len()));
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < count;
        // Logs beyond the configured budget cannot keep a worker alive.
        for byte in &buffer[..keep] {
            if *byte == b'\n' {
                if !oversized_line && tracker.observe(&line) {
                    generation = generation.saturating_add(1);
                    progress.send_replace(generation);
                }
                line.clear();
                oversized_line = false;
            } else if line.len() < MAX_PROGRESS_LINE_BYTES {
                line.push(*byte);
            } else {
                oversized_line = true;
            }
        }
    }
    Ok((retained, truncated))
}

pub(crate) async fn wait_with_progress<F, T>(
    completion: F,
    budget: std::time::Duration,
    mut progress: watch::Receiver<u64>,
) -> std::result::Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(completion);
    let mut deadline = tokio::time::Instant::now() + budget;
    loop {
        tokio::select! {
            result = &mut completion => return Ok(result),
            _ = tokio::time::sleep_until(deadline) => return Err(()),
            changed = progress.changed() => {
                if changed.is_err() {
                    return tokio::time::timeout_at(deadline, &mut completion).await.map_err(|_| ());
                }
                progress.borrow_and_update();
                deadline = tokio::time::Instant::now() + budget;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_advancing_work_extends_the_deadline() {
        let mut tracker = ProgressTracker::default();
        assert!(!tracker.observe(b"depgraph-progress phase=go_syntax status=started"));
        assert!(!tracker.observe(b"heartbeat"));
        assert!(tracker.observe(b"depgraph-progress phase=go_syntax status=progress items=10"));
        assert!(!tracker.observe(b"depgraph-progress phase=go_syntax status=progress items=10"));
        assert!(!tracker.observe(b"depgraph-progress phase=go_syntax status=progress items=9"));
        assert!(tracker.observe(b"depgraph-progress phase=go_syntax status=progress items=11"));
        assert!(tracker.observe(b"depgraph-progress phase=go_syntax status=completed items=11"));
        assert!(!tracker.observe(b"depgraph-progress phase=go_syntax status=completed items=11"));
        assert!(!tracker.observe(b"depgraph-progress phase=../bad status=completed"));
    }

    #[tokio::test(start_paused = true)]
    async fn progressing_unit_can_run_longer_than_the_inactivity_budget() {
        use std::time::Duration;
        let (sender, receiver) = watch::channel(0);
        tokio::spawn(async move {
            for generation in 1..=4 {
                tokio::time::sleep(Duration::from_secs(200)).await;
                sender.send_replace(generation);
            }
        });
        let started = tokio::time::Instant::now();
        let completion = async {
            tokio::time::sleep(Duration::from_secs(900)).await;
            "completed"
        };
        assert_eq!(
            wait_with_progress(completion, Duration::from_secs(300), receiver).await,
            Ok("completed")
        );
        assert_eq!(started.elapsed(), Duration::from_secs(900));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_or_closed_progress_stream_keeps_its_deadline() {
        use std::time::Duration;
        let (sender, receiver) = watch::channel(0);
        let completion = std::future::pending::<()>();
        assert!(
            wait_with_progress(completion, Duration::from_secs(300), receiver)
                .await
                .is_err()
        );
        let receiver = sender.subscribe();
        drop(sender);
        assert!(
            wait_with_progress(
                std::future::pending::<()>(),
                Duration::from_secs(300),
                receiver
            )
            .await
            .is_err()
        );
    }
}
