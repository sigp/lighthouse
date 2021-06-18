mod sign_randao {

    use helpers::*;

    #[test]
    fn happy_path() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let url = format!("{}/sign/{}", test_signer.address, PUBLIC_KEY_1);
        let test_randao_body = get_test_randao_body(0xc137);

        let response = http_post_custom_body(&url, &test_randao_body);
        assert_sign_ok(response, HAPPY_PATH_RANDAO_SIGNATURE_C137);

        test_signer.shutdown();
    }

    #[test]
    fn domain_mismatch() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let url = format!("{}/sign/{}", test_signer.address, PUBLIC_KEY_1);

        let testcase = |json_patch, expected_err| {
            let test_randao_body = get_test_randao_body(0xc137).replace(
                "\"bls_domain\":\"randao\"",
                &format!("\"bls_domain\":{}", json_patch),
            );
            let response = http_post_custom_body(&url, &test_randao_body);
            assert_sign_error(response, 400, expected_err);
        };

        testcase(
            "\"beacon_proposer\"",
            "Unable to parse block from JSON: Error(\"invalid type: string \"49463\", expected struct BeaconBlock\", line: 0, column: 0)"
        );
        testcase(
            "\"beacon_attester\"",
            "Unable to parse attestation from JSON: Error(\"invalid type: string \"49463\", expected struct AttestationData\", line: 0, column: 0)"
        );
        testcase("\"blah\"", "Unsupported bls_domain parameter: blah");

        test_signer.shutdown();
    }

    #[test]
    fn invalid_field_data() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let url = format!("{}/sign/{}", test_signer.address, PUBLIC_KEY_1);

        let testcase = |json_patch, expected_err| {
            let test_randao_body = get_test_randao_body(0xc137)
                .replace(",\"data\":\"49463\"", &format!(",\"data\":{}", json_patch));
            let response = http_post_custom_body(&url, &test_randao_body);
            assert_sign_error(response, 400, expected_err);
        };

        testcase(
            "",
            "Unable to parse body message from JSON: Error(\"expected value\", line: 1, column: 31)"
        );
        testcase(
            "\"\"",
            "Unable to parse attestation from JSON: Error(\"cannot parse integer from empty string\", line: 0, column: 0)"
        );
        testcase(
            "\"-1\"",
            "Unable to parse attestation from JSON: Error(\"invalid digit found in string\", line: 0, column: 0)"
        );
        testcase(
            "true",
            "Unable to parse attestation from JSON: Error(\"invalid type: boolean `true`, expected a quoted or unquoted integer\", line: 0, column: 0)"
        );
        testcase(
            "{\"cats\":\"3\"}",
            "Unable to parse attestation from JSON: Error(\"invalid type: map, expected a quoted or unquoted integer\", line: 0, column: 0)",
        );
        testcase(
            "[\"a\"]",
            "Unable to parse attestation from JSON: Error(\"invalid type: sequence, expected a quoted or unquoted integer\", line: 0, column: 0)"
        );

        test_signer.shutdown();
    }
}
