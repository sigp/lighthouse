#[cfg(not(target_family = "windows"))]
mod not_windows {
    use execution_engine_integration::{Geth, TestRig};
    #[test]
    fn geth() {
        TestRig::new(Geth).perform_tests_blocking()
    }
}

#[cfg(target_family = "windows")]
mod windows {
    #[test]
    fn all_tests_skipped_on_windows() {
        //
    }
}
