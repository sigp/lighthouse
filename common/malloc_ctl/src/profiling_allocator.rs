use crate::DEFAULT_MMAP_THRESHOLD;
use parking_lot::RwLock;
use std::alloc::{GlobalAlloc, Layout, System};
use std::backtrace::Backtrace;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref IN_USE: RwLock<bool> = <_>::default();
}

pub struct ProfilingAllocator;

unsafe impl GlobalAlloc for ProfilingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);


        if layout.size() >= DEFAULT_MMAP_THRESHOLD as usize {
            let mut in_use = IN_USE.write();

            if !*in_use {
                *in_use = true;
                drop(in_use);

                let backtrace = Backtrace::capture().to_string();
                eprintln!("alloc {}, {}, {}", layout.size(), *ret, backtrace);

                *IN_USE.write() = false;
            }
        }

        return ret;
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= DEFAULT_MMAP_THRESHOLD as usize {
            eprintln!("dealloc {}, {}", layout.size(), *ptr);
        }

        System.dealloc(ptr, layout);
    }
}
