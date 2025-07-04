#![deny(unsafe_code)]
#![deny(missing_docs)]
//! Scheduler module: async job queue and cron-style tasks.


use tokio::time::{Duration};
use chrono;
use std::collections::BinaryHeap;
use std::cmp::Reverse;

/// Represents a scheduled job.
#[derive(Debug, Clone)]
pub struct ScheduledJob {
    /// When to run the job (epoch seconds)
    pub run_at: u64,
    /// Job name or type
    pub job_type: String,
}

/// Simple async scheduler for EDR jobs.
pub struct Scheduler {
    queue: BinaryHeap<Reverse<ScheduledJob>>,
}

impl Scheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        Scheduler { queue: BinaryHeap::new() }
    }

    /// Schedule a job at a given time.
    pub fn schedule(&mut self, job: ScheduledJob) {
        self.queue.push(Reverse(job));
    }

    /// Run the scheduler loop (polls for due jobs).
    pub async fn run(&mut self) {
        loop {
            let now = chrono::Utc::now().timestamp() as u64;
            while let Some(Reverse(job)) = self.queue.peek() {
                if job.run_at <= now {
                    match self.queue.pop() {
                        Some(rj) => {
                            // TODO: dispatch job
                            let _ = rj.0;
                        },
                        None => {
                            eprintln!("[ERROR] Scheduler queue pop failed unexpectedly");
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

impl PartialEq for ScheduledJob {
    fn eq(&self, other: &Self) -> bool {
        self.run_at == other.run_at && self.job_type == other.job_type
    }
}
impl Eq for ScheduledJob {}
impl PartialOrd for ScheduledJob {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ScheduledJob {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.run_at.cmp(&other.run_at)
    }
}
