//! A fixed-size worker thread pool with a bounded job queue.
//!
//! The old server spawned one OS thread per connection with no upper limit, so
//! a burst of connections (or a slow-client attack) could exhaust the machine.
//! Here the number of threads is fixed, and when the queue is full new
//! connections are refused immediately instead of piling up.

use std::{
    panic::{self, AssertUnwindSafe},
    sync::{
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread,
};

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Handle for submitting work. Cloning it is cheap and all clones feed the
/// same workers, so several listeners can share one pool.
#[derive(Clone)]
pub struct ThreadPool {
    sender: SyncSender<Job>,
}

impl ThreadPool {
    /// Starts `workers` threads that pull jobs from a queue holding at most
    /// `queue` waiting jobs.
    pub fn new(workers: usize, queue: usize) -> Self {
        assert!(workers > 0, "a pool needs at least one worker");

        let (sender, receiver) = mpsc::sync_channel::<Job>(queue);
        // `Receiver` is single-consumer, so the workers take turns locking it.
        let receiver = Arc::new(Mutex::new(receiver));

        for id in 0..workers {
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("worker-{id}"))
                .spawn(move || loop {
                    // Hold the lock only while waiting for the next job, never
                    // while running it, or the other workers would be blocked.
                    let next = {
                        let guard = receiver.lock().unwrap_or_else(|p| p.into_inner());
                        guard.recv()
                    };
                    match next {
                        // A panicking handler must not take its worker with it,
                        // or the pool would slowly shrink to nothing.
                        Ok(job) => {
                            if panic::catch_unwind(AssertUnwindSafe(job)).is_err() {
                                eprintln!("  worker-{id}: a request handler panicked");
                            }
                        }
                        Err(_) => break, // every sender is gone: shut down
                    }
                })
                .expect("failed to spawn worker thread");
        }

        ThreadPool { sender }
    }

    /// Queues `job`. Returns `false`, dropping the job, when the queue is full
    /// (or the pool has shut down). Dropping a job that owns a connection
    /// closes that connection.
    pub fn try_execute<F>(&self, job: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        match self.sender.try_send(Box::new(job)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        sync::mpsc::channel,
        time::Duration,
    };

    #[test]
    fn runs_every_submitted_job() {
        let pool = ThreadPool::new(4, 64);
        let (tx, rx) = channel();
        for i in 0..50 {
            let tx = tx.clone();
            assert!(pool.try_execute(move || tx.send(i).unwrap()));
        }
        let mut got: Vec<i32> = (0..50).map(|_| rx.recv_timeout(Duration::from_secs(2)).unwrap()).collect();
        got.sort();
        assert_eq!(got, (0..50).collect::<Vec<_>>());
    }

    #[test]
    fn never_runs_more_jobs_at_once_than_it_has_workers() {
        let pool = ThreadPool::new(3, 64);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (done_tx, done_rx) = channel();

        for _ in 0..20 {
            let (running, peak, done_tx) = (running.clone(), peak.clone(), done_tx.clone());
            assert!(pool.try_execute(move || {
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
                running.fetch_sub(1, Ordering::SeqCst);
                done_tx.send(()).unwrap();
            }));
        }
        for _ in 0..20 {
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 3, "peak concurrency {}", peak.load(Ordering::SeqCst));
    }

    #[test]
    fn rejects_work_when_the_queue_is_full() {
        // One worker, queue of one: block the worker, fill the queue, then overflow.
        let pool = ThreadPool::new(1, 1);
        let (release_tx, release_rx) = channel::<()>();
        let (started_tx, started_rx) = channel();

        assert!(pool.try_execute(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().ok(); // hold the only worker
        }));
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        assert!(pool.try_execute(|| {}), "one job may wait in the queue");
        assert!(!pool.try_execute(|| {}), "the next one must be refused");

        release_tx.send(()).unwrap();
    }

    #[test]
    fn a_panicking_job_does_not_kill_its_worker() {
        let pool = ThreadPool::new(1, 8);
        assert!(pool.try_execute(|| panic!("boom (expected in this test)")));

        let (tx, rx) = channel();
        assert!(pool.try_execute(move || tx.send("still alive").unwrap()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), "still alive");
    }
}
