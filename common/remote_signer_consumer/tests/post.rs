mod post {
    use remote_signer_consumer::{Error, RemoteSignerHttpConsumer};
    use remote_signer_test::*;
    use reqwest::ClientBuilder;
    use sensitive_url::SensitiveUrl;
    use tokio::time::Duration;

    #[test]
    fn server_unavailable() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        test_signer.shutdown();

        let test_input = get_input_data_block(0xc137);
        let signature = do_sign_request(&test_client, test_input);

        match signature.unwrap_err() {
            Error::Reqwest(e) => {
                let error_msg = e.to_string();
                let pubkey_string = PUBLIC_KEY_1.to_string();
                let msgs = vec![
                    "error sending request for url",
                    &pubkey_string,
                    "error trying to connect",
                    "tcp connect error",
                    match cfg!(windows) {
                        true => "No connection could be made because the target machine actively refused it",
                        false => "Connection refused",
                    }
                ];
                for msg in msgs.iter() {
                    assert!(
                        error_msg.contains(msg),
                        "{:?} should contain {:?}",
                        error_msg,
                        msg
                    );
                }
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn server_error() {
        let (test_signer, tmp_dir) = set_up_api_test_signer_to_sign_message();
        restrict_permissions(tmp_dir.path());
        restrict_permissions(&tmp_dir.path().join(PUBLIC_KEY_1));

        let test_client = set_up_test_consumer(&test_signer.address);
        let test_input = get_input_data_block(0xc137);
        let signature = do_sign_request(&test_client, test_input);

        unrestrict_permissions(tmp_dir.path());
        unrestrict_permissions(&tmp_dir.path().join(PUBLIC_KEY_1));

        match signature.unwrap_err() {
            Error::ServerMessage(message) => assert_eq!(message, "Storage error: PermissionDenied"),
            e => panic!("{:?}", e),
        }

        test_signer.shutdown();
    }

    #[test]
    fn invalid_url() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();

        let run_testcase = |u: &str| -> Result<String, String> {
            let url = SensitiveUrl::parse(u).map_err(|e| format!("{:?}", e))?;

            let reqwest_client = ClientBuilder::new()
                .timeout(Duration::from_secs(12))
                .build()
                .unwrap();

            let test_client = RemoteSignerHttpConsumer::from_components(url, reqwest_client);

            let test_input = get_input_data_block(0xc137);
            let signature = do_sign_request(&test_client, test_input);

            signature.map_err(|e| match e {
                Error::InvalidUrl(message) => format!("{:?}", message),
                Error::Reqwest(re) => {
                    if re.is_builder() {
                        format!("[Reqwest - Builder] {:?}", re.url().unwrap())
                    } else if re.is_request() {
                        format!("[Reqwest - Request] {:?}", re.url().unwrap())
                    } else {
                        format!("[Reqwest] {:?}", re)
                    }
                }
                _ => format!("{:?}", e),
            })
        };

        let testcase = |u: &str, msg: &str| assert_eq!(run_testcase(u).unwrap_err(), msg);

        // url::parser::ParseError.
        // These cases don't even make it to the step of building a RemoteSignerHttpConsumer.
        testcase("", "ParseError(RelativeUrlWithoutBase)");
        testcase("/4/8/15/16/23/42", "ParseError(RelativeUrlWithoutBase)");
        testcase("localhost", "ParseError(RelativeUrlWithoutBase)");
        testcase(":", "ParseError(RelativeUrlWithoutBase)");
        testcase("0.0:0", "ParseError(RelativeUrlWithoutBase)");
        testcase(":aa", "ParseError(RelativeUrlWithoutBase)");
        testcase("0:", "ParseError(RelativeUrlWithoutBase)");
        testcase("ftp://", "ParseError(EmptyHost)");
        testcase("http://", "ParseError(EmptyHost)");
        testcase("http://127.0.0.1:abcd", "ParseError(InvalidPort)");
        testcase("http://280.0.0.1", "ParseError(InvalidIpv4Address)");

        // `Error::InvalidUrl`.
        // The RemoteSignerHttpConsumer is created, but fails at `path_segments_mut()`.
        testcase("localhost:abcd", "InvalidUrl(\"URL cannot be a base.\")");
        testcase("localhost:", "InvalidUrl(\"URL cannot be a base.\")");

        // `Reqwest::Error` of the `Builder` kind.
        // POST is not made.
        testcase(
            "unix:/run/foo.socket",
            &format!(
                "[Reqwest - Builder] Url {{ scheme: \"unix\", username: \"\", password: None, host: None, port: None, path: \"/run/foo.socket/sign/{}\", query: None, fragment: None }}",
                PUBLIC_KEY_1
            ),
        );
        // `Reqwest::Error` of the `Request` kind.
        testcase(
            "http://127.0.0.1:0",
            &format!(
                "[Reqwest - Request] Url {{ scheme: \"http\", username: \"\", password: None, host: Some(Ipv4(127.0.0.1)), port: Some(0), path: \"/sign/{}\", query: None, fragment: None }}",
                PUBLIC_KEY_1
            ),
        );

        test_signer.shutdown();
    }

    #[test]
    fn wrong_url() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();

        let run_testcase = |u: &str| -> Result<String, String> {
            let url = SensitiveUrl::parse(u).unwrap();

            let reqwest_client = ClientBuilder::new()
                .timeout(Duration::from_secs(12))
                .build()
                .unwrap();

            let test_client = RemoteSignerHttpConsumer::from_components(url, reqwest_client);

            let test_input = get_input_data_block(0xc137);
            let signature = do_sign_request(&test_client, test_input);

            signature.map_err(|e| format!("{:?}", e))
        };

        let testcase = |u: &str, msgs: Vec<&str>| {
            let r = run_testcase(u).unwrap_err();
            for msg in msgs.iter() {
                assert!(r.contains(msg), "{:?} should contain {:?}", r, msg);
            }
        };

        testcase(
            "http://error-dns",
            vec![
                "reqwest::Error",
                "kind: Request",
                &format!("/sign/{}", PUBLIC_KEY_1),
                "hyper::Error(Connect, ConnectError",
                "dns error",
                match cfg!(windows) {
                    true => "No such host is known.",
                    false => "failed to lookup address information",
                },
            ],
        );

        test_signer.shutdown();
    }

    #[test]
    fn wrong_public_key() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        let mut test_input = get_input_data_block(0xc137);
        test_input.public_key = ABSENT_PUBLIC_KEY.to_string();

        let signature = do_sign_request(&test_client, test_input);

        match signature.unwrap_err() {
            Error::ServerMessage(msg) => {
                assert_eq!(msg, format!("Key not found: {}", ABSENT_PUBLIC_KEY))
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn invalid_secret_key() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        let mut test_input = get_input_data_block(0xc137);
        test_input.public_key = PUBLIC_KEY_FOR_INVALID_SECRET_KEY.to_string();

        let signature = do_sign_request(&test_client, test_input);

        match signature.unwrap_err() {
            Error::ServerMessage(msg) => assert_eq!(
                msg,
                format!(
                    "Invalid secret key: public_key: {}; Invalid hex character: W at index 0",
                    PUBLIC_KEY_FOR_INVALID_SECRET_KEY
                )
            ),
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn key_mismatch() {
        let (test_signer, _tmp_dir) = set_up_api_test_signer_to_sign_message();
        let test_client = set_up_test_consumer(&test_signer.address);

        let mut test_input = get_input_data_block(0xc137);
        test_input.public_key = MISMATCHED_PUBLIC_KEY.to_string();

        let signature = do_sign_request(&test_client, test_input);

        match signature.unwrap_err() {
            Error::ServerMessage(msg) => {
                assert_eq!(msg, format!("Key mismatch: {}", MISMATCHED_PUBLIC_KEY))
            }
            e => panic!("{:?}", e),
        }
    }
}
