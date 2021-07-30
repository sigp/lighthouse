use super::*;
use compare_fields::{CompareFields, Comparison, FieldComparison};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use types::BeaconState;

pub const MAX_VALUE_STRING_LEN: usize = 500;

#[derive(Debug, PartialEq, Clone)]
pub struct CaseResult {
    pub case_index: usize,
    pub desc: String,
    pub path: PathBuf,
    pub result: Result<(), Error>,
}

impl CaseResult {
    pub fn new(
        case_index: usize,
        path: &Path,
        case: &impl Case,
        result: Result<(), Error>,
    ) -> Self {
        CaseResult {
            case_index,
            desc: case.description(),
            path: path.into(),
            result,
        }
    }
}

/// Same as `compare_result_detailed`, however it drops the caches on both states before
/// comparison.
pub fn compare_beacon_state_results_without_caches<T: EthSpec, E: Debug>(
    result: &mut Result<BeaconState<T>, E>,
    expected: &mut Option<BeaconState<T>>,
) -> Result<(), Error> {
    if let (Ok(ref mut result), Some(ref mut expected)) = (result.as_mut(), expected.as_mut()) {
        result.drop_all_caches().unwrap();
        expected.drop_all_caches().unwrap();
    }

    compare_result_detailed(result, expected)
}

/// Same as `compare_result`, however utilizes the `CompareFields` trait to give a list of
/// mismatching fields when `Ok(result) != Some(expected)`.
pub fn compare_result_detailed<T, E>(
    result: &Result<T, E>,
    expected: &Option<T>,
) -> Result<(), Error>
where
    T: PartialEq<T> + Debug + CompareFields,
    E: Debug,
{
    match (result, expected) {
        (Ok(result), Some(expected)) => {
            let mut mismatching_fields: Vec<Comparison> = expected
                .compare_fields(result)
                .into_iter()
                // Filter all out all fields that are equal.
                .filter(Comparison::not_equal)
                .collect();

            mismatching_fields
                .iter_mut()
                .for_each(|f| f.retain_children(FieldComparison::not_equal));

            if !mismatching_fields.is_empty() {
                Err(Error::NotEqual(format!(
                    "Fields not equal (a = expected, b = result): {:#?}",
                    mismatching_fields
                )))
            } else {
                Ok(())
            }
        }
        _ => compare_result(result, expected),
    }
}

/// Compares `result` with `expected`.
///
/// If `expected.is_none()` then `result` is expected to be `Err`. Otherwise, `T` in `result` and
/// `expected` must be equal.
pub fn compare_result<T, E>(result: &Result<T, E>, expected: &Option<T>) -> Result<(), Error>
where
    T: PartialEq<T> + Debug,
    E: Debug,
{
    match (result, expected) {
        // Pass: The should have failed and did fail.
        (Err(_), None) => Ok(()),
        // Fail: The test failed when it should have produced a result (fail).
        (Err(e), Some(expected)) => Err(Error::NotEqual(format!(
            "Got {:?} | Expected {}",
            e,
            fmt_val(expected)
        ))),
        // Fail: The test produced a result when it should have failed (fail).
        (Ok(result), None) => Err(Error::DidntFail(format!("Got {:?}", fmt_val(result)))),
        // Potential Pass: The test should have produced a result, and it did.
        (Ok(result), Some(expected)) => {
            if result == expected {
                Ok(())
            } else {
                Err(Error::NotEqual(format!(
                    "Got {} | Expected {}",
                    fmt_val(result),
                    fmt_val(expected)
                )))
            }
        }
    }
}

fn fmt_val<T: Debug>(val: T) -> String {
    let mut string = format!("{:?}", val);
    string.truncate(MAX_VALUE_STRING_LEN);
    string
}
