use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

/// Executes the function with a specified number of retries if the function returns an error
/// that `should_retry` accepts. Once it exceeds `max_retries` and still fails, the error is
/// returned.
pub async fn with_retry_if<T, U, F, P>(
    max_retries: usize,
    should_retry: P,
    mut func: F,
) -> Result<T, U>
where
    F: FnMut() -> Pin<Box<dyn Future<Output = Result<T, U>>>>,
    P: Fn(&U) -> bool,
    U: Debug,
{
    let mut retry_count = 0;
    loop {
        let result = Box::pin(func()).await;
        let retryable = match &result {
            Ok(_) => false,
            Err(error) => should_retry(error),
        };
        if result.is_ok() || !retryable || retry_count >= max_retries {
            break result;
        }
        retry_count += 1;

        if let Err(e) = result {
            eprintln!(
                "Operation failed with error {:?}, retrying {} of {}",
                e, retry_count, max_retries
            );
        }
    }
}

/// Executes the function with a specified number of retries if the function returns an error.
/// Once it exceeds `max_retries` and still fails, the error is returned.
pub async fn with_retry<T, U, F>(max_retries: usize, func: F) -> Result<T, U>
where
    F: FnMut() -> Pin<Box<dyn Future<Output = Result<T, U>>>>,
    U: Debug,
{
    with_retry_if(max_retries, |_| true, func).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    async fn my_async_func(is_ok: bool) -> Result<(), ()> {
        if is_ok { Ok(()) } else { Err(()) }
    }

    #[tokio::test]
    async fn test_with_retry_ok() {
        let res = with_retry(3, || Box::pin(my_async_func(true))).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_with_retry_2nd_ok() {
        let mut mock_results = VecDeque::from([false, true]);
        let res = with_retry(3, || {
            Box::pin(my_async_func(mock_results.pop_front().unwrap()))
        })
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_with_retry_fail() {
        let res = with_retry(3, || Box::pin(my_async_func(false))).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_with_retry_if_retries_retryable_error() {
        let mut mock_results = VecDeque::from([
            Err("AddrInUse".to_string()),
            Err("AddrInUse".to_string()),
            Ok(()),
        ]);
        let res = with_retry_if(
            3,
            |e: &String| e.contains("AddrInUse"),
            || {
                let next = mock_results.pop_front().unwrap();
                Box::pin(async move { next })
            },
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_with_retry_if_skips_non_retryable_error() {
        let mut mock_results = VecDeque::from([Err("boom".to_string()), Ok(())]);
        let mut attempts = 0;
        let res = with_retry_if(
            3,
            |e: &String| e.contains("AddrInUse"),
            || {
                attempts += 1;
                let next = mock_results.pop_front().unwrap();
                Box::pin(async move { next })
            },
        )
        .await;
        assert!(res.is_err());
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn test_with_retry_if_gives_up_after_max_retries() {
        let mut attempts = 0;
        let res: Result<(), String> = with_retry_if(
            2,
            |_: &String| true,
            || {
                attempts += 1;
                Box::pin(async { Err("AddrInUse".to_string()) })
            },
        )
        .await;
        assert!(res.is_err());
        assert_eq!(attempts, 3);
    }
}
