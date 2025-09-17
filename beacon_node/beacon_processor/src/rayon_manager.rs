use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

const DEFAULT_LOW_PRIORITY_DIVISOR: usize = 4;
const MINIMUM_LOW_PRIORITY_THREAD_COUNT: usize = 1;

pub struct RayonManager {
    /// Smaller rayon thread pool for lower-priority, compute-intensive tasks.
    /// By default ~25% of CPUs or a minimum of 1 thread.
    pub low_priority_threadpool: Arc<ThreadPool>,
}

impl Default for RayonManager {
    fn default() -> Self {
        let low_prio_threads =
            (num_cpus::get() / DEFAULT_LOW_PRIORITY_DIVISOR).max(MINIMUM_LOW_PRIORITY_THREAD_COUNT);
        let low_priority_threadpool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(low_prio_threads)
                .build()
                .expect("failed to build low-priority rayon pool"),
        );
        Self {
            low_priority_threadpool,
        }
    }
}
