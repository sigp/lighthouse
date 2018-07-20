extern crate slog;
extern crate slog_term;
extern crate slog_async;

use slog::*;
pub use slog::Logger;

pub fn test_logger() -> slog::Logger {
    let plain = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
    let logger = Logger::root(
        slog_term::FullFormat::new(plain)
        .build().fuse(), o!()
    );
    logger
}

pub fn get_logger() -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    slog::Logger::root(drain, o!())
}
