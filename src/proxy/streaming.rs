//! Unified response body type plus the [`tee_stream`] adapter that lets the
//! proxy capture the upstream response while forwarding it unchanged.
//!
//! ### Tee semantics
//! [`tee_stream`] spawns a tokio task that pulls from the upstream and:
//! 1. Clones each chunk (cheap — `Bytes` is reference-counted) and forwards
//!    one copy to the client via an `mpsc::unbounded` channel.
//! 2. Accumulates the other copy in a `Vec<Bytes>`.
//! 3. When the upstream stream ends — successfully or otherwise — calls
//!    `on_complete` with the accumulated chunks so the caller can parse
//!    usage data and write storage rows.
//!
//! If the client disconnects mid-stream, the channel send fails; we keep
//! reading from upstream and still fire `on_complete` so cost tracking
//! reflects what the upstream actually delivered.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::stream::{Stream, StreamExt};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Response body for every reply the proxy emits. `UnsyncBoxBody` (not
/// `BoxBody`) because `reqwest::Response::bytes_stream()` is `Send` but not
/// always `Sync`; Hyper's server only needs `Send + 'static`.
pub type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

pub fn full(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

pub fn empty() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

/// Wrap a `Stream` of upstream bytes so it can be returned as a Hyper body.
/// No buffering — chunks are emitted as they arrive.
pub fn from_stream<S>(stream: S) -> ProxyBody
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
{
    let mapped = stream.map(|res| res.map(Frame::data).map_err(|e| Box::new(e) as BoxError));
    StreamBody::new(mapped).boxed_unsync()
}

/// Tee the upstream byte stream: forward every chunk to the returned
/// downstream stream, and after the upstream completes call `on_complete`
/// with the accumulated chunks (for usage parsing and storage). The
/// callback fires once per upstream stream, in a spawned task — fire-and-
/// forget from the caller's perspective.
pub fn tee_stream<S, F>(stream: S, on_complete: F) -> ChannelStream
where
    S: Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
    F: FnOnce(Vec<Bytes>) + Send + 'static,
{
    let (tx, rx) = unbounded_channel();
    tokio::spawn(async move {
        let mut collected: Vec<Bytes> = Vec::new();
        let mut stream = Box::pin(stream);
        let mut client_alive = true;
        while let Some(item) = stream.next().await {
            if let Ok(ref b) = item {
                collected.push(b.clone());
            }
            if client_alive && tx.send(item).is_err() {
                // Client closed — stop forwarding, but keep draining so we
                // still call on_complete with the full accumulated body.
                client_alive = false;
            }
        }
        on_complete(collected);
    });
    ChannelStream(rx)
}

/// `Stream` adapter over an `mpsc::UnboundedReceiver` — used by
/// [`tee_stream`] to expose the teed downstream side as something
/// [`from_stream`] can consume.
pub struct ChannelStream(UnboundedReceiver<reqwest::Result<Bytes>>);

impl Stream for ChannelStream {
    type Item = reqwest::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}
