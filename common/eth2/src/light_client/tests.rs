use super::*;

#[test]
fn timed_out_decoder_keeps_its_permit_and_bounds_cloned_clients() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut server = mockito::Server::new_async().await;
        let response = server
            .mock("GET", "/data")
            .with_header("content-type", "application/json")
            .with_body("[]")
            .create_async()
            .await;
        let unexpected = server
            .mock("GET", "/unexpected")
            .expect(0)
            .create_async()
            .await;
        let client =
            LightClientHttpClient::new(SensitiveUrl::parse(&server.url()).unwrap()).unwrap();
        // Occupy the only blocking thread so the real JSON decoder queues deterministically.
        // Dropping the sender (also on panic) releases the blocker; runtime teardown cannot hang.
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = wait.blocking_recv();
        });
        ready.await.unwrap();
        let first = client
            .get_json::<serde_json::Value>(
                Url::parse(&format!("{}/data", server.url())).unwrap(),
                RequestLimits::new(Duration::from_millis(100), 2).unwrap(),
            )
            .await;
        let available = client.permit.available_permits();
        let second = client
            .clone()
            .get_json::<serde_json::Value>(
                Url::parse(&format!("{}/unexpected", server.url())).unwrap(),
                RequestLimits::new(Duration::from_millis(20), 2).unwrap(),
            )
            .await;
        drop(release);
        blocker.await.unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(1), client.permit.acquire())
            .await
            .expect("decoder releases permit when it actually finishes")
            .unwrap();
        drop(permit);

        let first = first.unwrap_err();
        assert!(matches!(first.kind, RequestErrorKind::Timeout), "{first:?}");
        assert_eq!(first.status, Some(StatusCode::OK));
        assert_eq!(first.bytes_received, 2);
        assert_eq!(available, 0);
        let second = second.unwrap_err();
        assert!(
            matches!(second.kind, RequestErrorKind::Timeout),
            "{second:?}"
        );
        assert_eq!(second.status, None);
        assert_eq!(second.bytes_received, 0);
        response.assert_async().await;
        unexpected.assert_async().await;
    });
}
