//! Provides a single-sender, multiple receiver one-shot channel where any message sent will be
//! received by all senders.
//!
//! This implementation may not be blazingly fast but it should be simple enough to be reliable.
use parking_lot::{Condvar, Mutex};
use std::sync::{Arc, Weak};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Error {
    SenderDropped,
}

enum Future<T> {
    /// The future is ready and the item may be consumed.
    Ready(T),
    /// Future is not ready. The contained `Weak` is a reference to the `Sender` that may be used to
    /// detect when the channel is disconnected.
    NotReady(Weak<()>),
}

struct MutexCondvar<T> {
    mutex: Mutex<Future<T>>,
    condvar: Condvar,
}

/// The sending pair of the `oneshot` channel.
pub struct Sender<T>(Arc<MutexCondvar<T>>, Option<Arc<()>>);

impl<T> Sender<T> {
    /// Send a message, consuming `self` and delivering the message to *all* receivers.
    pub fn send(self, item: T) {
        *self.0.mutex.lock() = Future::Ready(item);
        // Condvar notification will be handled by the `Drop` implementation.
    }
}

impl<T> Drop for Sender<T> {
    /// Drop the `Arc` and notify all receivers so they can't upgrade their `Weak`s and know that
    /// the sender has been dropped.
    fn drop(&mut self) {
        self.1 = None;
        self.0.condvar.notify_all();
    }
}

/// The receiving pair of the `oneshot` channel. Always receives the message sent by the `Sender`
/// (if any).
#[derive(Clone)]
pub struct Receiver<T: Clone>(Arc<MutexCondvar<T>>);

impl<T: Clone> Receiver<T> {
    /// Check to see if there is a message to be read *without* blocking/waiting.
    ///
    /// ## Note
    ///
    /// This method will technically perform *some* blocking to access a `Mutex`. It is non-blocking
    /// in the sense that it won't block until a message is received (i.e., it may return `Ok(None)`
    /// if no message has been sent yet).
    pub fn try_recv(&self) -> Result<Option<T>, Error> {
        match &*self.0.mutex.lock() {
            Future::Ready(item) => Ok(Some(item.clone())),
            Future::NotReady(weak) if weak.upgrade().is_some() => Ok(None),
            Future::NotReady(_) => Err(Error::SenderDropped),
        }
    }

    /// Check to see if there is a message to be read whilst blocking/waiting until a message is
    /// sent or the `Sender` is dropped.
    pub fn recv(self) -> Result<T, Error> {
        let mut lock = self.0.mutex.lock();
        loop {
            match &*lock {
                Future::Ready(item) => return Ok(item.clone()),
                Future::NotReady(weak) if weak.upgrade().is_some() => {
                    self.0.condvar.wait(&mut lock)
                }
                Future::NotReady(_) => return Err(Error::SenderDropped),
            }
        }
    }
}

/// A single-sender, multiple-receiver broadcast channel.
///
/// The sender may send *only one* message which will be received by *all* receivers.
pub fn oneshot<T: Clone>() -> (Sender<T>, Receiver<T>) {
    let sender_ref = Arc::new(());
    let mutex_condvar = Arc::new(MutexCondvar {
        mutex: Mutex::new(Future::NotReady(Arc::downgrade(&sender_ref))),
        condvar: Condvar::new(),
    });
    let receiver = Receiver(mutex_condvar.clone());
    let sender = Sender(mutex_condvar, Some(sender_ref));
    (sender, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn single_thread_try_recv() {
        let (sender, receiver) = oneshot();
        assert_eq!(receiver.try_recv(), Ok(None));
        sender.send(42);
        assert_eq!(receiver.try_recv(), Ok(Some(42)));
    }

    #[test]
    fn single_thread_try_recv_no_message() {
        let (sender, receiver) = oneshot::<u8>();
        assert_eq!(receiver.try_recv(), Ok(None));
        drop(sender);
        assert_eq!(receiver.try_recv(), Err(Error::SenderDropped));
    }

    #[test]
    fn single_thread_recv() {
        let (sender, receiver) = oneshot();
        assert_eq!(receiver.try_recv(), Ok(None));
        sender.send(42);
        assert_eq!(receiver.recv(), Ok(42));
    }

    #[test]
    fn single_thread_recv_no_message() {
        let (sender, receiver) = oneshot::<u8>();
        assert_eq!(receiver.try_recv(), Ok(None));
        drop(sender);
        assert_eq!(receiver.recv(), Err(Error::SenderDropped));
    }

    #[test]
    fn two_threads_message_sent() {
        let (sender, receiver) = oneshot();

        let handle = thread::spawn(|| receiver.recv().unwrap());

        sender.send(42);
        assert_eq!(handle.join().unwrap(), 42);
    }

    #[test]
    fn three_threads_message_set() {
        let (sender, receiver) = oneshot();

        let receiver_a = receiver.clone();
        let handle_a = thread::spawn(|| receiver_a.recv().unwrap());
        let handle_b = thread::spawn(|| receiver.recv().unwrap());

        sender.send(42);
        assert_eq!(handle_a.join().unwrap(), 42);
        assert_eq!(handle_b.join().unwrap(), 42);
    }

    #[test]
    fn three_threads_sender_dropped() {
        let (sender, receiver) = oneshot::<u8>();

        let receiver_a = receiver.clone();
        let handle_a = thread::spawn(|| receiver_a.recv());
        let handle_b = thread::spawn(|| receiver.recv());

        drop(sender);
        assert_eq!(handle_a.join().unwrap(), Err(Error::SenderDropped));
        assert_eq!(handle_b.join().unwrap(), Err(Error::SenderDropped));
    }

    #[test]
    fn sender_dropped_after_recv() {
        let (sender_a, receiver_a) = oneshot();
        let (sender_b, receiver_b) = oneshot::<u8>();

        let handle_0 = thread::spawn(|| {
            sender_a.send(1);
            receiver_b.recv()
        });

        assert_eq!(receiver_a.recv(), Ok(1));
        // This is a slightly hacky sleep that assumes that the thread has had enough time after
        // sending down `sender_a` to start listening to `receiver_b`.
        thread::sleep(Duration::from_secs(1));
        drop(sender_b);
        assert_eq!(handle_0.join().unwrap(), Err(Error::SenderDropped))
    }
}
