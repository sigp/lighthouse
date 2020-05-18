use crate::case_result::CaseResult;
use crate::error::Error;
use std::path::Path;

pub fn assert_tests_pass(handler_name: &str, path: &Path, results: &[CaseResult]) {
    let (failed, skipped_bls, skipped_known_failures) = categorize_results(results);

    if failed.len() + skipped_known_failures.len() > 0 {
        print_results(
            handler_name,
            &failed,
            &skipped_bls,
            &skipped_known_failures,
            &results,
        );
        if !failed.is_empty() {
            panic!("Tests failed (see above)");
        }
    } else {
        println!("Passed {} tests in {}", results.len(), path.display());
    }
}

pub fn categorize_results(
    results: &[CaseResult],
) -> (Vec<&CaseResult>, Vec<&CaseResult>, Vec<&CaseResult>) {
    let mut failed = vec![];
    let mut skipped_bls = vec![];
    let mut skipped_known_failures = vec![];

    for case in results {
        match case.result.as_ref().err() {
            Some(Error::SkippedBls) => skipped_bls.push(case),
            Some(Error::SkippedKnownFailure) => skipped_known_failures.push(case),
            Some(_) => failed.push(case),
            None => (),
        }
    }

    (failed, skipped_bls, skipped_known_failures)
}

pub fn print_results(
    handler_name: &str,
    failed: &[&CaseResult],
    skipped_bls: &[&CaseResult],
    skipped_known_failures: &[&CaseResult],
    results: &[CaseResult],
) {
    println!("--------------------------------------------------");
    println!(
        "Test {}",
        if failed.is_empty() {
            "Result"
        } else {
            "Failure"
        }
    );
    println!("Title: {}", handler_name);
    println!(
        "{} tests, {} failed, {} skipped (known failure), {} skipped (bls), {} passed. (See below for errors)",
        results.len(),
        failed.len(),
        skipped_known_failures.len(),
        skipped_bls.len(),
        results.len() - skipped_bls.len() - skipped_known_failures.len() - failed.len()
    );
    println!();

    for case in skipped_known_failures {
        println!("-------");
        println!(
            "case ({}) from {} skipped because it's a known failure",
            case.desc,
            case.path.display()
        );
    }
    for failure in failed {
        let error = failure.result.clone().unwrap_err();

        println!("-------");
        println!(
            "case {} ({}) from {} failed with {}:",
            failure.case_index,
            failure.desc,
            failure.path.display(),
            error.name()
        );
        println!("{}", error.message());
    }
    println!();
}
