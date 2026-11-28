//! Lifetime tracking counts producer destruction, not the lifetime of a join waiter.

use futures::future::Either;
use std::future::Future;
use tokio_util::task::TaskTracker;
use tokio_util::task::task_tracker::{TaskTrackerToken, TrackedFuture};

/// Wait for actual tracked producers, including blocking closures whose join waiter was dropped.
/// Closing does not prevent an existing producer from creating a tracked child during cleanup.
pub async fn wait_for_tracked_tasks(tracker: &TaskTracker, timeout: std::time::Duration) -> bool {
    tracker.close();
    tokio::time::timeout(timeout, tracker.wait()).await.is_ok()
}

pub(super) fn future<F: Future>(
    tracker: Option<&TaskTracker>,
    future: F,
) -> Either<TrackedFuture<F>, F> {
    match tracker {
        Some(tracker) => Either::Left(tracker.track_future(future)),
        None => Either::Right(future),
    }
}

/// Fields intentionally drop in this order: producer captures (which may emit final records)
/// must be destroyed before releasing the token, including a closure that never starts.
pub(super) struct Work<F> {
    work: F,
    _token: Option<TaskTrackerToken>,
}

impl<F> Work<F> {
    pub(super) fn new(tracker: Option<&TaskTracker>, work: F) -> Self {
        Self {
            work,
            _token: tracker.map(TaskTracker::token),
        }
    }
}

impl<F, R> Work<F>
where
    F: FnOnce() -> R,
{
    pub(super) fn run(self) -> Output<R> {
        let Self { work, _token } = self;
        Output {
            value: work(),
            _token,
        }
    }
}

/// An abandoned result may own a measurement completion guard. Retain tracking until it is
/// destroyed, or until an already-tracked async consumer takes ownership of the value.
pub(super) struct Output<R> {
    value: R,
    _token: Option<TaskTrackerToken>,
}

impl<R> Output<R> {
    pub(super) fn into_inner(self) -> R {
        let Self { value, _token } = self;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HandleProvider, TaskExecutor};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct FinalRecord(Arc<AtomicBool>);
    impl Drop for FinalRecord {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    fn executor(tracker: &TaskTracker) -> (TaskExecutor, async_channel::Sender<()>) {
        let (exit_tx, exit_rx) = async_channel::bounded(1);
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor = TaskExecutor::new(
            HandleProvider::Handle(tokio::runtime::Handle::current()),
            exit_rx,
            shutdown_tx,
        )
        .with_task_tracker(tracker.clone());
        (executor, exit_tx)
    }

    #[tokio::test]
    async fn cancelled_future_drops_producer_before_tracker_completes() {
        let tracker = TaskTracker::new();
        let (executor, exit_tx) = executor(&tracker);
        let recorded = Arc::new(AtomicBool::new(false));
        let final_record = FinalRecord(recorded.clone());
        executor.spawn(
            async move {
                let _final_record = final_record;
                std::future::pending::<()>().await;
            },
            "tracking_cancel_test",
        );
        tracker.close();
        assert!(!tracker.is_empty());
        drop(exit_tx);
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
        assert!(recorded.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn aborted_unpolled_future_destroys_capture_before_token() {
        let tracker = TaskTracker::new();
        let (executor, _exit_tx) = executor(&tracker);
        let recorded = Arc::new(AtomicBool::new(false));
        let final_record = FinalRecord(recorded.clone());
        let task = executor
            .spawn_handle(
                async move {
                    let _final_record = final_record;
                    std::future::pending::<()>().await;
                },
                "tracking_unpolled_test",
            )
            .unwrap();
        tracker.close();
        task.abort();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
        assert!(recorded.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn blocking_join_waiter_drop_does_not_release_running_producer() {
        let tracker = TaskTracker::new();
        let (executor, _exit_tx) = executor(&tracker);
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let recorded = Arc::new(AtomicBool::new(false));
        let final_record = FinalRecord(recorded.clone());
        let waiter = executor
            .spawn_blocking_handle(
                move || {
                    let _record = final_record;
                    let _ = started.send(());
                    wait.recv().unwrap();
                },
                "tracking_blocking_test",
            )
            .unwrap();
        running.await.unwrap();
        drop(waiter);
        tracker.close();
        assert!(!tracker.is_empty());
        assert!(!recorded.load(Ordering::Acquire));
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
        assert!(recorded.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn closed_tracker_still_waits_for_descendants_and_without_exit_tasks() {
        let tracker = TaskTracker::new();
        let (executor, _exit_tx) = executor(&tracker);
        let child_executor = executor.clone();
        let events = Arc::new(Mutex::new(Vec::new()));
        let child_events = events.clone();
        let (go, ready) = tokio::sync::oneshot::channel();
        executor.spawn_without_exit(
            async move {
                ready.await.unwrap();
                child_executor.spawn_without_exit(
                    async move {
                        child_events.lock().unwrap().push("child final record");
                    },
                    "tracking_child_test",
                );
            },
            "tracking_parent_test",
        );
        tracker.close();
        go.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), tracker.wait())
            .await
            .unwrap();
        assert_eq!(*events.lock().unwrap(), vec!["child final record"]);
    }

    #[tokio::test]
    async fn unfinished_producer_wait_is_bounded_without_aborting_native_work() {
        let tracker = TaskTracker::new();
        let token = tracker.token();
        tracker.close();
        assert!(
            tokio::time::timeout(Duration::from_millis(1), tracker.wait())
                .await
                .is_err()
        );
        assert_eq!(tracker.len(), 1);
        drop(token);
        tracker.wait().await;
    }

    #[tokio::test]
    async fn cancelled_rayon_waiter_keeps_native_producer_tracked() {
        let tracker = TaskTracker::new();
        let (executor, _exit_tx) = executor(&tracker);
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let recorded = Arc::new(AtomicBool::new(false));
        let final_record = FinalRecord(recorded.clone());
        let waiter = tokio::spawn(async move {
            executor
                .spawn_blocking_with_rayon_async(crate::RayonPoolType::LowPriority, move || {
                    let _record = final_record;
                    let _ = started.send(());
                    wait.recv().unwrap();
                })
                .await
        });
        running.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        tracker.close();
        assert_eq!(tracker.len(), 1);
        assert!(!recorded.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert!(wait_for_tracked_tasks(&tracker, Duration::from_secs(1)).await);
        assert!(recorded.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn never_started_work_drops_capture_before_finishing_tracking() {
        let tracker = TaskTracker::new();
        let recorded = Arc::new(AtomicBool::new(false));
        let final_record = FinalRecord(recorded.clone());
        let work = Work::new(Some(&tracker), move || drop(final_record));
        tracker.close();
        drop(work);
        tracker.wait().await;
        assert!(recorded.load(Ordering::Acquire));
    }

    struct ReturnedRecord {
        tracker: TaskTracker,
        dropped: Option<tokio::sync::oneshot::Sender<bool>>,
    }

    impl Drop for ReturnedRecord {
        fn drop(&mut self) {
            if let Some(dropped) = self.dropped.take() {
                let _ = dropped.send(!self.tracker.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn abandoned_blocking_result_emits_before_tracker_is_empty() {
        let tracker = TaskTracker::new();
        let (executor, _exit_tx) = executor(&tracker);
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let (dropped, drop_observed) = tokio::sync::oneshot::channel();
        let result_tracker = tracker.clone();
        let waiter = executor
            .spawn_blocking_handle(
                move || {
                    let _ = started.send(());
                    wait.recv().unwrap();
                    ReturnedRecord {
                        tracker: result_tracker,
                        dropped: Some(dropped),
                    }
                },
                "tracking_abandoned_result_test",
            )
            .unwrap();
        running.await.unwrap();
        drop(waiter);
        tracker.close();
        release.send(()).unwrap();
        assert!(
            drop_observed.await.unwrap(),
            "returned completion dropped after tracking ended"
        );
        assert!(wait_for_tracked_tasks(&tracker, Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn abandoned_rayon_result_emits_before_tracker_is_empty() {
        let tracker = TaskTracker::new();
        let (executor, _exit_tx) = executor(&tracker);
        let (release, wait) = std::sync::mpsc::channel();
        let (started, running) = tokio::sync::oneshot::channel();
        let (dropped, drop_observed) = tokio::sync::oneshot::channel();
        let result_tracker = tracker.clone();
        let waiter = tokio::spawn(async move {
            executor
                .spawn_blocking_with_rayon_async(crate::RayonPoolType::LowPriority, move || {
                    let _ = started.send(());
                    wait.recv().unwrap();
                    ReturnedRecord {
                        tracker: result_tracker,
                        dropped: Some(dropped),
                    }
                })
                .await
        });
        running.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        tracker.close();
        release.send(()).unwrap();
        assert!(
            drop_observed.await.unwrap(),
            "returned completion dropped after tracking ended"
        );
        assert!(wait_for_tracked_tasks(&tracker, Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn output_destructor_must_finish_before_export_drain_can_start() {
        struct SlowFinalRecord {
            entered: Option<tokio::sync::oneshot::Sender<()>>,
            release: std::sync::mpsc::Receiver<()>,
            recorded: Arc<AtomicBool>,
        }
        impl Drop for SlowFinalRecord {
            fn drop(&mut self) {
                let _ = self.entered.take().unwrap().send(());
                self.release.recv().unwrap();
                self.recorded.store(true, Ordering::Release);
            }
        }
        let tracker = TaskTracker::new();
        let recorded = Arc::new(AtomicBool::new(false));
        let (entered, dropping) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let final_record = SlowFinalRecord {
            entered: Some(entered),
            release: wait,
            recorded: recorded.clone(),
        };
        let output = Work::new(Some(&tracker), move || final_record).run();
        tracker.close();
        let dropper = std::thread::spawn(move || drop(output));
        dropping.await.unwrap();
        assert_eq!(tracker.len(), 1);
        assert!(!wait_for_tracked_tasks(&tracker, Duration::from_millis(1)).await);
        assert!(!recorded.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert!(wait_for_tracked_tasks(&tracker, Duration::from_secs(1)).await);
        assert!(recorded.load(Ordering::Acquire));
        dropper.join().unwrap();
    }
}
