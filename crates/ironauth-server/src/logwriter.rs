// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal non-blocking log writer.
//!
//! A background thread performs the blocking `stdout` writes, so request
//! threads only pay a channel send per log line and never block on I/O. This
//! replaces `tracing-appender`'s non-blocking writer to keep the `time` crate
//! (which that crate pulls only for its file-rolling feature, unused here) out
//! of the dependency graph; that removal fixes both an MSRV floor and a
//! transitive advisory. The guard flushes and joins the worker on drop.

use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use tracing_subscriber::fmt::MakeWriter;

/// A message to the writer thread.
enum Message {
    /// One formatted log line (or fragment) to write.
    Line(Vec<u8>),
    /// Flush and stop; the worker acks so the guard can join cleanly.
    Shutdown(Sender<()>),
}

/// A cloneable, non-blocking `MakeWriter` handing bytes to a worker thread.
#[derive(Clone)]
pub struct NonBlocking {
    tx: Sender<Message>,
}

/// Keeps the writer thread alive. Dropping it flushes buffered output and joins
/// the worker, so nothing is lost at shutdown.
pub struct WriterGuard {
    tx: Sender<Message>,
    worker: Option<JoinHandle<()>>,
}

/// Start the background writer targeting `stdout`.
#[must_use]
pub fn stdout() -> (NonBlocking, WriterGuard) {
    let (tx, rx) = mpsc::channel::<Message>();
    let worker = std::thread::Builder::new()
        .name("ironauth-log".to_owned())
        .spawn(move || run(&rx))
        .expect("spawn log writer thread");
    (
        NonBlocking { tx: tx.clone() },
        WriterGuard {
            tx,
            worker: Some(worker),
        },
    )
}

/// The worker loop: write each line, and stop on `Shutdown` after a final flush.
fn run(rx: &Receiver<Message>) {
    let mut out = io::stdout().lock();
    while let Ok(message) = rx.recv() {
        match message {
            Message::Line(bytes) => {
                let _ = out.write_all(&bytes);
                let _ = out.flush();
            }
            Message::Shutdown(ack) => {
                let _ = out.flush();
                let _ = ack.send(());
                break;
            }
        }
    }
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.tx.send(Message::Shutdown(ack_tx)).is_ok() {
            // Wait for the worker to flush everything queued ahead of shutdown.
            let _ = ack_rx.recv();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The per-event writer: buffers the line, then ships it on flush (which the
/// fmt layer calls at the end of each event, and `Drop` guarantees).
pub struct LineWriter {
    tx: Sender<Message>,
    buf: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            // A closed channel (worker already shut down) drops the line; at
            // that point the process is exiting anyway.
            let _ = self.tx.send(Message::Line(std::mem::take(&mut self.buf)));
        }
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let _ = Write::flush(self);
    }
}

impl<'a> MakeWriter<'a> for NonBlocking {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter {
            tx: self.tx.clone(),
            buf: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_reach_stdout_worker_and_guard_joins() {
        // Smoke test: a line written through the MakeWriter is accepted and the
        // guard drop flushes and joins without hanging.
        let (writer, guard) = stdout();
        let mut handle = writer.make_writer();
        handle.write_all(b"{\"probe\":1}\n").expect("buffered");
        handle.flush().expect("shipped");
        drop(handle);
        drop(guard);
    }
}
