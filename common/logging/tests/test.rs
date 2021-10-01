use std::env;
use std::process::Command;
use std::process::Output;

fn run_cmd(cmd_line: &str) -> Result<Output, std::io::Error> {
    let output;
    if cfg!(target_os = "windows") {
        output = Command::new(r#"cmd"#).args(["/C", cmd_line]).output();
    } else {
        output = Command::new(r#"sh"#).args(["-c", cmd_line]).output();
    }
    output
}

#[test]
fn test_test_logger_with_feature_test_logger() {
    let cur_dir = env::current_dir().unwrap();
    let test_dir = cur_dir
        .join("..")
        .join("..")
        .join("testing")
        .join("test-test_logger");
    let cmd_line = format!(
        "cd {} && cargo test --features logging/test_logger",
        test_dir.to_str().unwrap()
    );

    let output = run_cmd(&cmd_line);

    // Assert output data DOES contain "INFO hi, "
    let data = String::from_utf8(output.unwrap().stderr).unwrap();
    println!("data={}", data);
    assert!(data.contains("INFO hi, "));
}

#[test]
fn test_test_logger_no_features() {
    // Test without features
    let cur_dir = env::current_dir().unwrap();
    let test_dir = cur_dir
        .join("..")
        .join("..")
        .join("testing")
        .join("test-test_logger");
    let cmd_line = format!("cd {} && cargo test", test_dir.to_str().unwrap());

    let output = run_cmd(&cmd_line);

    // Assert output data DOES contain "INFO hi, "
    let data = String::from_utf8(output.unwrap().stderr).unwrap();
    println!("data={}", data);
    assert!(!data.contains("INFO hi, "));
}
