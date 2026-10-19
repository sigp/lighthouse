use beacon_chain::test_utils::EphemeralHarnessType;
use flate2::read::GzDecoder;
use http_metrics::Config;
use logging::create_test_tracing_subscriber;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE, VARY};
use std::error::Error;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use types::Spec;

type Context = http_metrics::Context<EphemeralHarnessType<Spec>>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_200_ok() -> Result<(), Box<dyn Error>> {
    assert_metrics_response(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_gzip_compressed_metrics() -> Result<(), Box<dyn Error>> {
    assert_metrics_response(true).await
}

async fn assert_metrics_response(gzip: bool) -> Result<(), Box<dyn Error>> {
    create_test_tracing_subscriber();

    let metric_name = if gzip {
        "http_metrics_gzip_test_value"
    } else {
        "http_metrics_plain_test_value"
    };
    let gauge = metrics::try_create_int_gauge(metric_name, "Metrics response test value")?;
    gauge.set(42);

    let context = Arc::new(Context {
        config: Config {
            enabled: true,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            listen_port: 0,
            allow_origin: None,
            allocator_metrics_enabled: false,
        },
        chain: None,
        db_path: None,
        freezer_db_path: None,
        gossipsub_registry: None,
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (listening_socket, server) = http_metrics::serve(context, async {
        let _ = shutdown_rx.await;
    })
    .await?;
    let server = tokio::spawn(server);

    // Inspect the wire response even if another crate enables reqwest's gzip feature.
    let client = reqwest::Client::builder()
        .no_gzip()
        .timeout(Duration::from_secs(10))
        .build()?;
    let mut request = client.get(format!("http://{listening_socket}/metrics"));
    if gzip {
        request = request.header(ACCEPT_ENCODING, "gzip");
    }
    let response = request.send().await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE),
        Some(&"text/plain".parse()?)
    );
    if gzip {
        assert_eq!(
            response.headers().get(CONTENT_ENCODING),
            Some(&"gzip".parse()?)
        );
        assert!(response.headers().get_all(VARY).iter().any(|value| {
            value.to_str().is_ok_and(|value| {
                value
                    .split(',')
                    .any(|name| name.trim().eq_ignore_ascii_case("accept-encoding"))
            })
        }));
    } else {
        assert!(!response.headers().contains_key(CONTENT_ENCODING));
    }

    let bytes = response.bytes().await?;
    let body = if gzip {
        let mut body = String::new();
        GzDecoder::new(bytes.as_ref()).read_to_string(&mut body)?;
        body
    } else {
        String::from_utf8(bytes.to_vec())?
    };
    assert!(body.contains(&format!("# TYPE {metric_name} gauge\n")));
    assert!(body.lines().any(|line| line == format!("{metric_name} 42")));

    assert!(shutdown_tx.send(()).is_ok());
    tokio::time::timeout(Duration::from_secs(10), server).await??;
    Ok(())
}
