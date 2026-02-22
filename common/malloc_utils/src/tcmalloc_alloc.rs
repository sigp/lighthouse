//! Set the allocator to `tcmalloc` (via gperftools).

#[global_allocator]
static ALLOC: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

pub fn scrape_tcmalloc_metrics() {
    // Metrics for tcmalloc can be added in a follow-up.
}
