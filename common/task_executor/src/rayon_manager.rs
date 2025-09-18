use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

const DEFAULT_LOW_PRIORITY_CPU_PERCENTAGE: usize = 25;
const MINIMUM_LOW_PRIORITY_THREAD_COUNT: usize = 1;

const DEFAULT_HIGH_PRIORITY_CPU_PERCENTAGE: usize = 80;
const MINIMUM_HIGH_PRIORITY_THREAD_COUNT: usize = 3;

pub struct RayonManager {
    /// Smaller rayon thread pool for lower-priority, compute-intensive tasks.
    /// By default ~25% of CPUs or a minimum of 1 thread.
    pub low_priority_threadpool: Arc<ThreadPool>,
    /// Larger rayon thread pool for high-priority, compute-intensive tasks.
    /// By default ~80% of CPUs or a minimum of 3 threads.
    pub high_priority_threadpool: Arc<ThreadPool>,
}

impl Default for RayonManager {
    fn default() -> Self {
        let low_prio_threads = (num_cpus::get() * DEFAULT_LOW_PRIORITY_CPU_PERCENTAGE / 100)
            .max(MINIMUM_LOW_PRIORITY_THREAD_COUNT);
        let low_priority_threadpool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(low_prio_threads)
                .build()
                .expect("failed to build low-priority rayon pool"),
        );

        let high_prio_threads = (num_cpus::get() * DEFAULT_HIGH_PRIORITY_CPU_PERCENTAGE / 100)
            .max(MINIMUM_HIGH_PRIORITY_THREAD_COUNT);
        let high_priority_threadpool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(high_prio_threads)
                .build()
                .expect("failed to build high-priority rayon pool"),
        );
        Self {
            low_priority_threadpool,
            high_priority_threadpool,
        }
    }
}
