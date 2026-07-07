//! Shared test helpers.

use std::net::TcpListener;

/// Serialize CPU/thread-heavy integration tests across the whole workspace so
/// they don't contend (many concurrent multi-node TCP tests + CPU-bound SLH-DSA
/// tests would otherwise starve each other's timing). Holding the returned
/// listener holds the lock; the OS frees the port if a test process dies, so
/// there is no stale-lock problem. The same port is used by the SLH tests.
#[must_use]
pub fn serial() -> TcpListener {
    loop {
        if let Ok(l) = TcpListener::bind("127.0.0.1:59717") {
            return l;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
