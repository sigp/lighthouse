use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;

const DEFAULT_LOW_PRIORITY_CPU_PERCENTAGE: usize = 25;
const DEFAULT_HIGH_PRIORITY_CPU_PERCENTAGE: usize = 80;
const MINIMUM_THREAD_COUNT: usize = 1;

pub enum RayonPoolType {
    HighPriority,
    LowPriority,
}

pub struct RayonPoolProvider {
    /// Smaller rayon thread pool for lower-priority, compute-intensive tasks.
    /// By default ~25% of CPUs or a minimum of 1 thread.
    low_priority_thread_pool: Arc<ThreadPool>,
    /// Larger rayon thread pool for high-priority, compute-intensive tasks.
    /// By default ~80% of CPUs or a minimum of 1 thread. Citical/highest
    /// priority tasks should use the global pool instead.
    high_priority_thread_pool: Arc<ThreadPool>,
}

impl Default for RayonPoolProvider {
    fn default() -> Self {
        let low_prio_threads =
            (num_cpus::get() * DEFAULT_LOW_PRIORITY_CPU_PERCENTAGE / 100).max(MINIMUM_THREAD_COUNT);
        let low_priority_thread_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(low_prio_threads)
                .build()
                .expect("failed to build low-priority rayon pool"),
        );

        let high_prio_threads = (num_cpus::get() * DEFAULT_HIGH_PRIORITY_CPU_PERCENTAGE / 100)
            .max(MINIMUM_THREAD_COUNT);
        let high_priority_thread_pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(high_prio_threads)
                .build()
                .expect("failed to build high-priority rayon pool"),
        );
        Self {
            low_priority_thread_pool,
            high_priority_thread_pool,
        }
    }
}

impl RayonPoolProvider {
    /// Get a scoped thread pool by priority level.
    /// For critical/highest priority tasks, use the global pool instead.
    pub fn get_thread_pool(&self, rayon_pool_type: RayonPoolType) -> Arc<ThreadPool> {
        match rayon_pool_type {
            RayonPoolType::HighPriority => self.high_priority_thread_pool.clone(),
            RayonPoolType::LowPriority => self.low_priority_thread_pool.clone(),
        }
    }
}
