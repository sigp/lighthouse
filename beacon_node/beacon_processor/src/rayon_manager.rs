use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

const LOW_PRIORITY_THREAD_COUNT: usize = 1;

pub struct RayonManager {
    /// Smaller rayon thread pool for lower-priority, compute-intensive tasks.
    /// By default limited to one thread.
    pub low_priority_threadpool: Arc<ThreadPool>,
}

impl Default for RayonManager {
    fn default() -> Self {
        let low_priority_threadpool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(LOW_PRIORITY_THREAD_COUNT)
                .build()
                .expect("failed to build low-priority rayon pool"),
        );
        Self {
            low_priority_threadpool,
        }
    }
}
