mod get_keys {
    use client::api_response::KeysApiResponse;
    use helpers::*;

    fn assert_ok(resp: ApiTestResponse, expected_keys_len: usize) {
        assert_eq!(resp.status, 200);
        assert_eq!(
            serde_json::from_value::<KeysApiResponse>(resp.json)
                .unwrap()
                .keys
                .len(),
            expected_keys_len
        );
    }

    fn assert_error(resp: ApiTestResponse, http_status: u16, error_msg: &str) {
        assert_eq!(resp.status, http_status);
        assert_eq!(resp.json["error"], error_msg);
    }

    #[test]
    fn all_files_in_dir_are_public_keys() {
        let (test_signer, tmp_dir) = set_up_api_test_signer_raw_dir();
        add_key_files(&tmp_dir);

        let url = format!("{}/keys", test_signer.address);

        let resp = http_get(&url);
        assert_ok(resp, 3);

        test_signer.shutdown();
    }

    #[test]
    fn some_files_in_dir_are_public_keys() {
        let (test_signer, tmp_dir) = set_up_api_test_signer_raw_dir();
        add_sub_dirs(&tmp_dir);
        add_key_files(&tmp_dir);
        add_non_key_files(&tmp_dir);

        let url = format!("{}/keys", test_signer.address);

        let resp = http_get(&url);
        assert_ok(resp, 3);

        test_signer.shutdown();
    }

    #[test]
    fn no_files_in_dir_are_public_keys() {
        let (test_signer, tmp_dir) = set_up_api_test_signer_raw_dir();
        add_sub_dirs(&tmp_dir);
        add_non_key_files(&tmp_dir);

        let url = format!("{}/keys", test_signer.address);

        let resp = http_get(&url);
        assert_error(resp, 404, "No keys found in storage.");

        test_signer.shutdown();
    }

    #[test]
    fn directory_failure() {
        let (test_signer, tmp_dir) = set_up_api_test_signer_raw_dir();
        add_sub_dirs(&tmp_dir);
        add_key_files(&tmp_dir);
        add_non_key_files(&tmp_dir);

        // Somebody tripped over a wire.
        restrict_permissions(tmp_dir.path());

        let url = format!("{}/keys", test_signer.address);

        let resp = http_get(&url);

        // Be able to delete the tempdir afterward, regardless of this test result.
        unrestrict_permissions(tmp_dir.path());

        assert_error(resp, 500, "Storage error: PermissionDenied");

        test_signer.shutdown();
    }
}
