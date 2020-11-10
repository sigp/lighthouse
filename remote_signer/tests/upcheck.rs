mod upcheck {
    use helpers::*;

    #[test]
    fn happy_path() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_raw_dir();

        let url = format!("{}/upcheck", test_signer.address);

        let resp = http_get(&url);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.json["status"], "OK");

        test_signer.shutdown();
    }
}
