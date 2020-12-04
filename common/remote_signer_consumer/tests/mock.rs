mod mock {
    use remote_signer_consumer::Error;
    use remote_signer_test::*;

    #[test]
    fn timeout() {
        let mock_server =
            set_up_mock_server_with_timeout(200, "{\"signature\":\"irrelevant_value\"}", 2);
        let test_client = set_up_test_consumer_with_timeout(&mock_server.url(""), 1);
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::Reqwest(e) => {
                let error_msg = e.to_string();
                assert!(error_msg.contains("error sending request for url (http://127.0.0.1:"));
                assert!(error_msg.contains("/sign/"));
                assert!(error_msg.contains(PUBLIC_KEY_1));
                assert!(error_msg.contains("): operation timed out"));
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn no_json_in_ok_response() {
        let mock_server = set_up_mock_server(200, "NO JSON");
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::Reqwest(e) => {
                let error_msg = e.to_string();
                assert_eq!(
                    error_msg,
                    "error decoding response body: expected value at line 1 column 1"
                );
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn missing_signature_in_ok_json() {
        let mock_server = set_up_mock_server(200, "{\"foo\":\"bar\"}");
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::Reqwest(e) => {
                let error_msg = e.to_string();
                assert_eq!(
                    error_msg,
                    "error decoding response body: missing field `signature` at line 1 column 13"
                );
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn empty_signature_in_ok_json() {
        let mock_server = set_up_mock_server(200, "{\"signature\":\"\"}");
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap();

        assert_eq!(r, "");
    }

    #[test]
    fn extra_fields_in_ok_json() {
        let mock_server = set_up_mock_server(
            200,
            &format!(
                "{{\"signature\":\"{}\", \"foo\":\"bar\", \"red\":\"green\"}}",
                EXPECTED_SIGNATURE_1
            ),
        );
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap();

        assert_eq!(r, EXPECTED_SIGNATURE_1);
    }

    #[test]
    fn no_json_in_error_response() {
        let mock_server = set_up_mock_server(500, "NO JSON");
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::Reqwest(e) => {
                let error_msg = e.to_string();
                assert_eq!(
                    error_msg,
                    "error decoding response body: expected value at line 1 column 1"
                );
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn missing_error_field_in_error_json() {
        let mock_server = set_up_mock_server(500, "{\"foo\":\"bar\"}");
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::Reqwest(e) => {
                let error_msg = e.to_string();
                assert_eq!(
                    error_msg,
                    "error decoding response body: missing field `error` at line 1 column 13"
                );
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn empty_error_field_in_error_json() {
        let mock_server = set_up_mock_server(500, "{\"error\":\"\"}");
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::ServerMessage(msg) => {
                assert_eq!(msg, "");
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn extra_fields_in_error_json() {
        let mock_server = set_up_mock_server(
            500,
            "{\"error\":\"some_error_msg\", \"foo\":\"bar\", \"red\":\"green\"}",
        );
        let test_client = set_up_test_consumer(&mock_server.url(""));
        let test_input = get_input_data_block(0xc137);

        let r = do_sign_request(&test_client, test_input).unwrap_err();

        match r {
            Error::ServerMessage(msg) => {
                assert_eq!(msg, "some_error_msg");
            }
            e => panic!("{:?}", e),
        }
    }
}
