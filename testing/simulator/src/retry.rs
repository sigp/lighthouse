use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

/// Executes the function with a specified number of retries if the function returns an error.
/// Once it exceeds `max_retries` and still fails, the error is returned.
pub async fn with_retry<T, E, F>(max_retries: usize, mut func: F) -> Result<T, E>
where
    F: FnMut() -> Pin<Box<dyn Future<Output = Result<T, E>>>>,
    E: Debug,
{
    let mut retry_count = 0;
    loop {
        let result = Box::pin(func()).await;
        if result.is_ok() || retry_count >= max_retries {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    async fn my_async_func(is_ok: bool) -> Result<(), ()> {
        if is_ok {
            Ok(())
        } else {
            Err(())
        }
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
}
