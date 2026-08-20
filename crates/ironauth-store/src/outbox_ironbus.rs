// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronBus-backed [`OutboxBackbone`](crate::outbox::OutboxBackbone) (issue #104).
//!
//! # What this is, and what it deliberately is not
//!
//! It is a WAKE-UP signal, not a transport. The outbox row remains the durable source of
//! truth in every mode; this only replaces the `poll_interval` wait with "a producer said
//! there is work". The reasoning lives on [`OutboxBackbone`](crate::outbox::OutboxBackbone)
//! and is the reason a lost bus message can cost latency but never an event.
//!
//! # The blocking client on an async worker
//!
//! `ironbus-client` is a BLOCKING, thread-per-connection client (the broker is too), and
//! the drain runs on a tokio worker. Calling it inline would park a runtime thread inside
//! a socket read for the whole wait, which starves every other task on that thread.
//!
//! So the connection lives on its own std thread, and the async side talks to it through a
//! `tokio::sync::Notify`. The thread owns the socket for its lifetime; the async side never
//! touches it. That keeps the blocking API entirely off the runtime.
//!
//! # Failure is not the caller's problem
//!
//! A backbone that is down, unreachable, or misconfigured must never turn a successful
//! domain write into an error, and must never wedge the drain. Every failure here degrades
//! to exactly the Postgres-only behaviour: the signal thread reports the fault once and
//! stops, and `wait` falls back to sleeping out the deadline, which is what
//! [`PollOnly`](crate::outbox::PollOnly) does. A deployment whose broker dies keeps
//! draining on the poll, slower and correct.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ironbus_client::Client;
use ironbus_client::proto::PubBody;

use crate::outbox::OutboxBackbone;
use crate::scope::Scope;

/// The consumer-group PREFIX the drain subscribes under.
///
/// Each backbone instance appends a unique suffix, so every instance gets its OWN group.
/// That is deliberate and is the opposite of the usual work-queue arrangement.
///
/// A shared group means COMPETING consumers: the broker hands each message to exactly one
/// member. For a work queue that is the point. For a WAKE-UP it is exactly wrong, because
/// every process needs to re-drain, and a shared group would deliver the wake to one of
/// them and leave the rest asleep until their poll deadline. That is not a hypothetical:
/// it is what made the live-broker test fail while the reader thread was demonstrably
/// alive and subscribed, because the test's producer instance and its waiter instance
/// were competing members of one group.
///
/// A per-instance group gives fanout without needing the broker configured with a
/// broadcast group, so a deployment points at any IronBus and it behaves correctly.
const WAKE_GROUP_PREFIX: &str = "ironauth-outbox-drain";

/// Distinguishes the groups of two backbones in ONE process (the test makes two; a
/// process that ran two pools would too).
static WAKE_GROUP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How long the reader thread sleeps when the wake stream has nothing new.
///
/// Sub-second, because this is what sets the drain's wake latency, and it is a cheap
/// local socket read rather than the multi-second DATABASE poll this backbone exists to
/// replace.
const WAKE_POLL: Duration = Duration::from_millis(100);

/// An IronBus-backed wake-up backbone (issue #104).
pub struct IronBusBackbone {
    /// Signalled whenever the reader thread observes a wake on the bus.
    woken: Arc<tokio::sync::Notify>,
    /// The producer connection, on its own thread behind a mutex: the client is `&mut`
    /// per call and blocking, so it is never touched from async code.
    producer: std::sync::Mutex<Option<Client>>,
    /// Set once the reader thread has given up, so `wait` stops pretending a signal may
    /// arrive and simply sleeps the deadline out.
    reader_dead: Arc<AtomicBool>,
}

impl IronBusBackbone {
    /// Connect to `addr` and start the reader thread.
    ///
    /// # Errors
    ///
    /// The underlying client error when the broker is unreachable at construction. A
    /// caller that wants "use the bus if it is there" treats this as "fall back to
    /// [`PollOnly`](crate::outbox::PollOnly)" rather than a startup failure: the whole
    /// point of an OPTIONAL backbone is that its absence is a supported mode.
    pub fn connect(addr: &str) -> Result<Self, ironbus_client::ClientError> {
        let producer = Client::connect(addr)?;
        let woken = Arc::new(tokio::sync::Notify::new());
        let reader_dead = Arc::new(AtomicBool::new(false));

        // The reader owns its OWN connection. Sharing one with the producer would mean a
        // blocking fetch and a produce contending for the same socket and the same `&mut`.
        // Unique per instance: process id plus a counter, so two backbones in one process
        // (and two processes on one host) never share a group and therefore never steal
        // each other's wakes.
        let group = format!(
            "{WAKE_GROUP_PREFIX}-{}-{}",
            std::process::id(),
            WAKE_GROUP_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let mut reader = Client::connect(addr)?;
        let woken_thread = Arc::clone(&woken);
        let dead = Arc::clone(&reader_dead);
        std::thread::Builder::new()
            .name("ironauth-outbox-wake".to_owned())
            .spawn(move || {
                // The DEFAULT stream, with `subscribe` + `fetch` + `ack`: the path the
                // client's own documentation demonstrates. The named-stream calls
                // (`publish_to` / `stream_fetch`) are a separate protocol path that
                // returned nothing against a dev broker, and a wake that is published
                // where nobody is listening is indistinguishable from no backbone at all.
                // A wake carries no payload, so it needs no stream of its own; what it
                // does need is to arrive.
                if reader.subscribe(&group).is_err() {
                    dead.store(true, Ordering::Relaxed);
                    return;
                }
                // A fresh group starts at the BEGINNING of the stream, so the first
                // pass replays every wake the deployment has ever produced. Those are
                // noise: a wake means "work appeared since you started listening", and a
                // historical one says nothing about the queue now.
                //
                // So the first batch is acked and NOT signalled. Over-signalling is cheap
                // (one wasted re-drain that finds nothing) and under-signalling costs a
                // poll interval, so the bias is deliberate: only the FIRST batch is
                // treated as backlog, and everything after it wakes the drain even if it
                // arrived a moment before the subscription completed.
                let mut backlog_drained = false;
                loop {
                    let Ok(fetch) = reader.fetch(64) else {
                        // One report, then stand down. A reconnect loop here would hammer
                        // a down broker from every process, and the drain is already
                        // correct without us: `wait` falls back to the poll.
                        dead.store(true, Ordering::Relaxed);
                        return;
                    };
                    {
                        {
                            if fetch.messages.is_empty() {
                                // An empty pass proves the backlog is behind us.
                                backlog_drained = true;
                                std::thread::sleep(WAKE_POLL);
                                continue;
                            }
                            // Ack BEFORE signalling: an unacked wake is redelivered
                            // forever, while an acked-then-lost one costs one poll
                            // interval, which is the trade this design is built on.
                            let acks: Vec<(u64, u64)> = fetch
                                .messages
                                .iter()
                                .map(|m| (m.offset, m.generation))
                                .collect();
                            let _ = reader.ack_many(&acks);
                            if backlog_drained {
                                // `notify_waiters`, not `notify_one`: every worker should
                                // re-drain; a stored permit would wake exactly one.
                                woken_thread.notify_waiters();
                            }
                        }
                    }
                }
            })
            .map_err(|_| ironbus_client::ClientError::Io(std::io::Error::other("spawn")))?;

        Ok(Self {
            woken,
            producer: std::sync::Mutex::new(Some(producer)),
            reader_dead,
        })
    }

    /// Whether the reader thread has stood down, so no signal can arrive.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.reader_dead.load(Ordering::Relaxed)
    }
}

/// The body of ONE wake-up, as published to the broker.
///
/// Extracted so the shape can be asserted directly. The two facts below are load-bearing
/// and were, until issue #107's ordering criterion needed them, stated only in prose:
///
/// - `payload` is EMPTY. This backbone is a wake-up signal, not a transport, and the
///   emptiness is what makes that true rather than merely intended. It is also what lets
///   the ordering argument be made against the `OutboxBackbone` seam instead of against
///   IronBus specifically: a signal that carries no event cannot reorder events.
/// - `fire_and_forget` is FALSE. A fire-and-forget produce is not durably committed, so
///   the record is not visible to a `fetch` and every wake vanishes. That was the actual
///   cause of four failed live-broker runs.
fn wake_body(consumer: &str) -> PubBody<'_> {
    PubBody {
        flags: 0,
        timestamp_ms: 0,
        key: consumer.as_bytes(),
        headers: b"",
        dedup: None,
        // NOT fire-and-forget: the named-stream path (`publish_to`) accepts only
        // at-least-once server-ack, and the subscriber reads that stream. Producing to the
        // default stream instead is silently a no-op for this backbone, which is exactly
        // how the first live-broker run failed: every wake was published where nobody was
        // listening. IronBus's own round-trip test produces with `fire_and_forget: false`
        // and only then is the record visible to a `fetch`.
        fire_and_forget: false,
        payload: b"",
    }
}

impl OutboxBackbone for IronBusBackbone {
    fn notify(&self, consumer: &str, _scope: Scope) {
        // Infallible by contract. A produce that fails is dropped on the floor ON PURPOSE:
        // the row is already committed, the drain will find it on the poll, and returning
        // an error here would let a broker outage fail a domain write.
        let Ok(mut guard) = self.producer.lock() else {
            return;
        };
        let Some(client) = guard.as_mut() else {
            return;
        };
        let body = wake_body(consumer);
        if client.produce(&body).is_err() {
            // Drop the connection rather than keep a broken one: a later notify makes a
            // fresh one, and until then the poll covers us.
            *guard = None;
        }
    }

    fn wait<'a>(
        &'a self,
        _consumer: &'a str,
        max_wait: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if self.is_degraded() {
                // No signal can arrive, so do not pretend: this is PollOnly.
                tokio::time::sleep(max_wait).await;
                return;
            }
            // The deadline is never removed. That is what makes a lost signal cost
            // latency instead of an event.
            let _ = tokio::time::timeout(max_wait, self.woken.notified()).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::wake_body;

    /// A wake carries NO event data.
    ///
    /// This is the fact the issue #107 ordering argument rests on: the IronBus mode cannot
    /// reorder events because it never carries one. Asserted on the value rather than left
    /// in a doc comment, so a future change that started attaching a payload here would
    /// have to delete a failing test rather than quietly contradict a paragraph.
    #[test]
    fn a_wake_carries_no_payload() {
        let body = wake_body("outbox-events");
        assert!(
            body.payload.is_empty(),
            "the backbone is a wake-up signal, not a transport"
        );
        assert!(body.headers.is_empty(), "and it carries no headers either");
        assert_eq!(
            body.key, b"outbox-events",
            "the key names the consumer to wake, which is the whole content of a wake"
        );
        assert!(
            !body.fire_and_forget,
            "a fire-and-forget wake is not durably committed, so no subscriber can fetch it"
        );
    }
}
