//! Set the allocator to `tcmalloc` (via modern Google TCMalloc).

#[global_allocator]
static ALLOC: tcmalloc_better::TCMalloc = tcmalloc_better::TCMalloc;

pub fn scrape_tcmalloc_metrics() {
    // Metrics for tcmalloc can be added in a follow-up.
}
