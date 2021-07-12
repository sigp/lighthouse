mod sign_attestation {
    use helpers::*;

    #[test]
    fn happy_path() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let url = format!("{}/sign/{}", test_signer.address, PUBLIC_KEY_1);
        let test_attestation_body = get_test_attestation_body(0xc137);

        let response = http_post_custom_body(&url, &test_attestation_body);

        assert_sign_ok(response, HAPPY_PATH_ATT_SIGNATURE_C137);

        test_signer.shutdown();
    }

    #[test]
    fn domain_mismatch() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let url = format!("{}/sign/{}", test_signer.address, PUBLIC_KEY_1);

        let testcase = |json_patch, expected_err| {
            let test_attestation_body = get_test_attestation_body(0xc137).replace(
                "\"bls_domain\":\"beacon_attester\"",
                &format!("\"bls_domain\":{}", json_patch),
            );
            let response = http_post_custom_body(&url, &test_attestation_body);
            assert_sign_error(response, 400, expected_err);
        };

        testcase(
            "\"beacon_proposer\"",
            "Unable to parse block from JSON: Error(\"data did not match any variant of untagged enum BeaconBlock\", line: 0, column: 0)"
        );
        testcase(
            "\"randao\"",
            "Unable to parse attestation from JSON: Error(\"invalid type: map, expected a quoted or unquoted integer\", line: 0, column: 0)"
        );
        testcase("\"blah\"", "Unsupported bls_domain parameter: blah");

        test_signer.shutdown();
    }

    #[test]
    fn missing_or_invalid_fields_within_attestation_data() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let url = format!("{}/sign/{}", test_signer.address, PUBLIC_KEY_1);

        let testcase = |json_patch, expected_err| {
            let test_attestation_body = get_test_attestation_body(0xc137).replace(
                "\"data\":{\"slot\":\"49463\",\"index\":\"49463\"",
                json_patch,
            );
            let response = http_post_custom_body(&url, &test_attestation_body);
            assert_sign_error(response, 400, expected_err);
        };

        testcase(
            "\"data\":{\"slot\":\"a\",\"index\":49463",
            "Unable to parse attestation from JSON: Error(\"invalid digit found in string\", line: 0, column: 0)"
        );
        testcase(
            "\"data\":{\"slot\":\"\",\"index\":\"49463\"",
            "Unable to parse attestation from JSON: Error(\"cannot parse integer from empty string\", line: 0, column: 0)"
        );
        testcase(
            "\"data\":{\"slot\":-1,\"index\":\"49463\"",
            "Unable to parse attestation from JSON: Error(\"invalid type: integer `-1`, expected a quoted or unquoted integer\", line: 0, column: 0)"
        );
        testcase(
            "\"data\":{\"slot\":\"-1\",\"index\":\"49463\"",
            "Unable to parse attestation from JSON: Error(\"invalid digit found in string\", line: 0, column: 0)"
        );
        testcase(
            "\"data\":{\"index\":\"49463\"",
            "Unable to parse attestation from JSON: Error(\"missing field `slot`\", line: 0, column: 0)",
        );
        testcase(
            "\"data\":{\"slot\":\"49463\"",
            "Unable to parse attestation from JSON: Error(\"missing field `index`\", line: 0, column: 0)"
        );
        testcase(
            "\"data\":{\"slot\":\"49463\",\"index\":\"\"",
            "Unable to parse attestation from JSON: Error(\"cannot parse integer from empty string\", line: 0, column: 0)",
        );

        test_signer.shutdown();
    }
}
