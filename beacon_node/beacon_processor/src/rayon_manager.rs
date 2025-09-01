use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

pub const DEFAULT_LOW_PRIORITY_DIVISOR: usize = 4;
const MINIMUM_LOW_PRIORITY_THREAD_COUNT: usize = 2;

pub struct RayonManager {
    /// Smaller rayon thread pool for lower-priority, compute-intensive tasks.
    /// By default ~25% of CPUs or a minimum of 2 threads.
    pub low_priority_threadpool: Arc<ThreadPool>,
    /// Larger rayon thread pool for high-priority, compute-intensive tasks.
    /// By default 100% of CPUs.
    pub high_priority_threadpool: Arc<ThreadPool>,
}

impl RayonManager {
    pub fn new(low_prio_cpu_divisor: usize) -> Self {
        let low_prio_threads =
            (num_cpus::get() / low_prio_cpu_divisor).max(MINIMUM_LOW_PRIORITY_THREAD_COUNT);
        let low_priority_threadpool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(low_prio_threads)
                .build()
                .expect("failed to build low-priority rayon pool"),
        );
        let high_priority_threadpool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .expect("failed to build high-priority rayon pool"),
        );
        Self {
            low_priority_threadpool,
            high_priority_threadpool,
        }
    }
}
