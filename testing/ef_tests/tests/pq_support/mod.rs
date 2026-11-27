//! Run an explicitly selected PQ artifact without replacing the installed legacy fixtures.
#![allow(dead_code)]

use ef_tests::{Case, Error, Handler, LoadCase};
use rayon::prelude::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
};
use types::ForkName;

pub fn fixture_root() -> PathBuf {
    std::env::var_os("CONSENSUS_SPEC_TESTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("consensus-spec-tests"))
        .join("tests/minimal/pq")
}

fn directories(path: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    paths.sort();
    paths
}

pub fn run_handler<H: Handler>(handler: H) {
    let name = handler.handler_name();
    run_handler_as(handler, H::runner_name(), &name);
}

/// The override supports PQ containers whose Rust type has a fork suffix.
pub fn run_handler_as<H: Handler>(_handler: H, runner: &str, name: &str) {
    let root = fixture_root();
    let path = root.join(runner).join(&name);
    let cases: Vec<_> = directories(&path)
        .into_iter()
        .flat_map(|suite| directories(&suite))
        .collect();
    assert!(!cases.is_empty(), "no cases in {}", path.display());
    let execute = |(index, path): (usize, &PathBuf)| {
        let case_name = path.strip_prefix(&root).unwrap().to_string_lossy();
        let (outcome, detail) = match catch_unwind(AssertUnwindSafe(|| {
            H::Case::load_from_dir(path, ForkName::Pq)
        })) {
            Err(panic) => ("load_panic", panic_text(panic)),
            Ok(Err(error)) => (
                "load_error",
                format!("{}: {}", error.name(), error.message()),
            ),
            Ok(Ok(case)) => {
                match catch_unwind(AssertUnwindSafe(|| case.result(index, ForkName::Pq))) {
                    Err(panic) => ("panic", panic_text(panic)),
                    Ok(Ok(())) => ("passed", String::new()),
                    Ok(Err(error)) => {
                        let outcome = match error {
                            Error::SkippedBls => "skipped_bls",
                            Error::SkippedKnownFailure => "skipped_known_failure",
                            _ => "failed",
                        };
                        (outcome, format!("{}: {}", error.name(), error.message()))
                    }
                }
            }
        };
        json!({"case": case_name, "outcome": outcome, "detail": detail})
    };
    let results: Vec<Value> = if H::rayon_enabled() {
        cases.par_iter().enumerate().map(execute).collect()
    } else {
        cases.iter().enumerate().map(execute).collect()
    };
    let mut counts = BTreeMap::<String, usize>::new();
    for result in &results {
        *counts
            .entry(result["outcome"].as_str().unwrap().into())
            .or_default() += 1;
    }
    let report = json!({"runner": runner, "handler": name, "counts": counts, "cases": results});
    if let Some(output) = std::env::var_os("PQ_REFERENCE_RESULTS_DIR") {
        let path = PathBuf::from(output).join(runner);
        fs::create_dir_all(&path).unwrap();
        fs::write(
            path.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
    println!("PQ_REFERENCE {runner}/{name}: {}", json!(counts));
    for result in results
        .iter()
        .filter(|result| result["outcome"] != "passed")
        .take(10)
    {
        println!(
            "{}: {}: {}",
            result["case"], result["outcome"], result["detail"]
        );
    }
    let failures: usize = counts
        .iter()
        .filter(|(outcome, _)| {
            !matches!(
                outcome.as_str(),
                "passed" | "skipped_bls" | "skipped_known_failure"
            )
        })
        .map(|(_, count)| count)
        .sum();
    assert_eq!(
        failures, 0,
        "{runner}/{name}: case failures, see PQ_REFERENCE_RESULTS_DIR for every outcome"
    );
}

fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            panic
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
        })
        .unwrap_or_else(|| "non-string panic".into())
}

/// Record fixtures for which the client intentionally has no implementation.
/// These records are never classified as passing reference tests.
pub fn unsupported_handler(runner: &str, name: &str, detail: &str) {
    let root = fixture_root();
    let cases: Vec<_> = directories(&root.join(runner).join(name)).into_iter()
        .flat_map(|suite| directories(&suite))
        .map(|path| json!({"case": path.strip_prefix(&root).unwrap().to_string_lossy(), "outcome": "unsupported", "detail": detail}))
        .collect();
    assert!(!cases.is_empty());
    println!("PQ_REFERENCE {runner}/{name}: {} unsupported", cases.len());
    if let Some(output) = std::env::var_os("PQ_REFERENCE_RESULTS_DIR") {
        let path = PathBuf::from(output).join(runner);
        fs::create_dir_all(&path).unwrap();
        let report = json!({"runner": runner, "handler": name, "counts": {"unsupported": cases.len()}, "cases": cases});
        fs::write(
            path.join(format!("{name}.json")),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
}
