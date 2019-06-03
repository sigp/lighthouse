pub fn yaml_split_header_and_cases(mut yaml: String) -> (String, String) {
    let test_cases_start = yaml.find("\ntest_cases:\n").unwrap();
    // + 1 to skip the \n we used for matching.
    let mut test_cases = yaml.split_off(test_cases_start + 1);

    let end_of_first_line = test_cases.find("\n").unwrap();
    let test_cases = test_cases.split_off(end_of_first_line + 1);

    (yaml, test_cases)
}
