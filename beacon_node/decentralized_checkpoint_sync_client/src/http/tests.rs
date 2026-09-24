use super::*;
use std::time::Duration;

#[test]
fn transport_classification_uses_structured_causes_not_connect_or_error_text() {
    for (kind, retryable) in [
        (io::ErrorKind::ConnectionReset, true),
        (io::ErrorKind::ConnectionRefused, true),
        (io::ErrorKind::TimedOut, true),
        (io::ErrorKind::UnexpectedEof, true),
        (io::ErrorKind::InvalidData, false),
        (io::ErrorKind::PermissionDenied, false),
        (io::ErrorKind::Other, false),
    ] {
        assert_eq!(
            has_transient_io_cause(&io::Error::new(kind, "connection reset, timeout")),
            retryable
        );
    }
    let reset = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
    assert!(has_transient_io_cause(&io::Error::other(reset)));
    let reset = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
    assert!(!has_transient_io_cause(&io::Error::new(
        io::ErrorKind::InvalidData,
        reset
    )));
}

#[test]
fn timeout_and_local_failures_preserve_the_original_error_and_usage() {
    for (kind, expected) in [
        (
            RequestErrorKind::Timeout,
            SourceErrorKind::Transient {
                retry_after: Some(Duration::from_secs(2)),
            },
        ),
        (
            RequestErrorKind::InvalidLimits,
            SourceErrorKind::Configuration,
        ),
        (
            RequestErrorKind::RuntimeUnavailable,
            SourceErrorKind::LocalFailure,
        ),
        (
            RequestErrorKind::AllocationFailed,
            SourceErrorKind::LocalFailure,
        ),
    ] {
        let error = source_error(RequestError {
            kind,
            status: None,
            retry_after: Some(Duration::from_secs(2)),
            bytes_received: 17,
        });
        assert_eq!(error.kind, expected);
        assert_eq!(error.bytes_received, 17);
        let cause = error
            .source
            .as_ref()
            .unwrap()
            .downcast_ref::<RequestError>()
            .unwrap();
        assert_eq!(cause.bytes_received, 17);
        assert_eq!(cause.retry_after, Some(Duration::from_secs(2)));
    }
}
