use crate::DEFAULT_MMAP_THRESHOLD;
use parking_lot::RwLock;
use std::alloc::{GlobalAlloc, Layout, System};
use std::backtrace::Backtrace;
use std::collections::HashMap;
use std::io::{self, Write};
use std::process;
use std::path::PathBuf;
use std::fs;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref STATS: RwLock<HashMap<String, Stat>> = <_>::default();
}

#[derive(Default, Clone)]
pub struct Stat {
    sum: usize,
    count: usize,
}

pub struct ProfilingAllocator;

unsafe impl GlobalAlloc for ProfilingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);

        if layout.size() >= DEFAULT_MMAP_THRESHOLD as usize {
            let backtrace = Backtrace::capture().to_string();

            let mut stat = STATS
                .read()
                .get(&backtrace)
                .cloned()
                .unwrap_or_default();

            stat.count = stat.count.saturating_add(1);
            stat.sum = stat.sum.saturating_add(layout.size());

            STATS.write().insert(backtrace.clone(), stat.clone());

            eprintln!("{} {} {}", stat.count, stat.sum, backtrace);
        }

        return ret;
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

impl ProfilingAllocator {
    fn dump(&self) -> Result<(), io::Error> {
        let mut path = PathBuf::new();
        path.push("tmp");
        path.push(format!("profiling_allocator_{}.csv", process::id()));

        let mut file = fs::File::create(&path)?;

        std::write!(file, "count,sum,backtrace\n")?;

        let stats = STATS.read();

        for (backtrace, stat) in stats.iter() {
            std::write!(
                file,
                "{},{},{}\n",
                stat.count, stat.sum, backtrace
            )?;
        }

        drop(stats);

        eprintln!("successfully dumped profile to {:?}", path);

        Ok(())
    }
}

impl Drop for ProfilingAllocator {
    fn drop(&mut self) {
        if let Err(e) = self.dump() {
            eprintln!("failed to dump profile: {}", e);
        }
    }
}
