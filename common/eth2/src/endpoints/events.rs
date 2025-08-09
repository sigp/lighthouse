//! Server-sent events API endpoints.

use crate::client::{BeaconNodeHttpClient, Error, V1};
use crate::types::*;
use futures::Stream;
use futures_util::StreamExt;
use reqwest_eventsource::{Event, EventSource};
use types::EthSpec;

impl BeaconNodeHttpClient {
    /// `GET events?topics`
    /// 
    /// Provides a stream of Server-Sent Events for specified beacon chain event topics.
    pub async fn get_events<E: EthSpec>(
        &self,
        topic: &[EventTopic],
    ) -> Result<impl Stream<Item = Result<EventKind<E>, Error>>, Error> {
        let mut path = self.eth_path(V1)?;
        path.path_segments_mut()
            .map_err(|()| Error::InvalidUrl(self.server().clone()))?
            .push("events");
        
        let topic_string = topic
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        path.query_pairs_mut().append_pair("topics", &topic_string);
        
        let mut es = EventSource::get(path);
        
        // If we don't await `Event::Open` here, then the consumer
        // will not get any Message events until they start awaiting the stream.
        // This is a way to register the stream with the sse server before
        // message events start getting emitted.
        while let Some(event) = es.next().await {
            match event {
                Ok(Event::Open) => break,
                Err(err) => return Err(Error::SseClient(err)),
                // This should never happen as we are guaranteed to get the
                // Open event before any message starts coming through.
                Ok(Event::Message(_)) => continue,
            }
        }
        
        Ok(Box::pin(es.filter_map(|event| async move {
            match event {
                Ok(Event::Open) => None,
                Ok(Event::Message(message)) => {
                    Some(EventKind::from_sse_bytes(&message.event, &message.data))
                }
                Err(err) => Some(Err(Error::SseClient(err))),
            }
        })))
    }
}