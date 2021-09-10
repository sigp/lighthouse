#[cfg(debug_assertions)] // Tests fail in release on github actions
#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn test_test_logger_with_feature_test_logger() {
        // Test with logging/test_logger feature
        let output = Command::new(r#"/usr/bin/bash"#)
            //.args(["-c", r#"ls -al"#])
            .args(["-c", r#"( cd tests/test-feature-test_logger ; cargo clean ; cargo test --features logging/test_logger)"#])
            .output();
        println!(
            "test_test_logger_with_feature_test_logger output: {:#?}",
            output
        );

        // Assert output data DOES contain "INFO hi, "
        let data = String::from_utf8(output.unwrap().stderr).unwrap();
        println!("data={}", data);
        assert!(data.contains("INFO hi, "));
    }

    #[test]
    fn test_test_logger_no_features() {
        // Test without features
        let output = Command::new(r#"/usr/bin/bash"#)
            .args([
                "-c",
                r#"( cd tests/test-feature-test_logger ; cargo test -- --nocapture )"#,
            ])
            .output();
        println!("test_test_logger_no_features output: {:#?}", output);

        // Assert output data DOES contain "INFO hi, "
        let data = String::from_utf8(output.unwrap().stderr).unwrap();
        println!("data={}", data);
        assert!(!data.contains("INFO hi, "));
    }
}
