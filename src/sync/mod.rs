extern crate futures;
extern crate slog;
extern crate tokio;

use super::p2p::service::NetworkService;
use self::futures::sync::mpsc::UnboundedReceiver;
use self::futures::Stream;
use slog::Logger;
use self::tokio::timer::Interval;
use self::tokio::prelude::*;

use std::time::{ Duration, Instant };

pub fn sync_start(service: NetworkService,
            net_stream: UnboundedReceiver<Vec<u8>>,
            log: Logger)
{
    let net_rx = net_stream
        .for_each(move |msg| {
            debug!(&log, "Sync receive"; "msg" => format!("{:?}", msg));
            // service.send("hello".to_bytes());
            Ok(())
        })
        .map_err(|_| panic!("rx failed"));

    let poll = Interval::new(Instant::now(), Duration::from_secs(2))
        .for_each(move |_| {
            service.send(vec![42, 42, 42]);
            Ok(())
        })
        .map_err(|_| panic!("send failed"));

    let sync_future = poll
        .select(net_rx).map_err(|(err, _)| err)
        .and_then(|((), n)| n);

    tokio::run(sync_future);
}
