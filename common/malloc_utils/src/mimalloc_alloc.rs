//! Set the allocator to `mimalloc`.

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub fn scrape_mimalloc_metrics() {
    // Metrics for mimalloc can be added in a follow-up.
}
