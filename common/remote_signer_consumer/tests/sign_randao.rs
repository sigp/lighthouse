mod sign_randao {
    use rand::Rng;
    use remote_signer_test::*;

    #[test]
    fn sanity_check_deterministic() {
        let test_input_local = get_input_local_signer_randao(0xc137);
        let local_signature = test_input_local.sign();

        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        let test_input = get_input_data_randao(0xc137);

        let remote_signature = do_sign_request(&test_client, test_input);

        assert_eq!(local_signature, remote_signature.unwrap());
        assert_eq!(local_signature, HAPPY_PATH_RANDAO_SIGNATURE_C137);
    }

    #[test]
    fn sanity_check_random() {
        let mut rng = rand::thread_rng();
        let seed = rng.gen::<u64>();

        let test_input_local = get_input_local_signer_randao(seed);
        let local_signature = test_input_local.sign();

        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        let test_input = get_input_data_randao(seed);

        let remote_signature = do_sign_request(&test_client, test_input);

        assert_eq!(local_signature, remote_signature.unwrap());
    }

    #[test]
    fn happy_path() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        let test_input = get_input_data_randao(0xc137);

        let remote_signature = do_sign_request(&test_client, test_input);

        assert_eq!(remote_signature.unwrap(), HAPPY_PATH_RANDAO_SIGNATURE_C137);
    }
}
