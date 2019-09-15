macro_rules! try_future {
    ($expr:expr) => {
        match $expr {
            core::result::Result::Ok(val) => val,
            core::result::Result::Err(err) => {
                return Box::new(futures::future::err(std::convert::From::from(err)))
            }
        }
    };
    ($expr:expr,) => {
        $crate::try_future!($expr)
    };
}
