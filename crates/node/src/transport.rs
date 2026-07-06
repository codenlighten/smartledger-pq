//! A minimal TCP gossip transport built on `std` threads — no async runtime.
//!
//! Model: each node **connects outbound** to every peer to send its own
//! broadcasts, and **accepts inbound** connections purely to receive. So every
//! pair shares two one-way channels. Outbound connections are established lazily
//! and reconnected on failure, which tolerates peers starting in any order.

use crate::event::Event;
use crate::frame::{read_frame, write_frame};
use crate::wire::WireMsg;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::thread;

pub struct Transport {
    listener: TcpListener,
    local_addr: SocketAddr,
    peers: Vec<String>,
    /// Lazily-opened send-only connections, parallel to `peers`.
    outbound: Vec<Option<TcpStream>>,
}

impl Transport {
    /// Bind the listen socket. Pass `127.0.0.1:0` to get an OS-assigned port,
    /// then read it back with [`Transport::local_addr`].
    pub fn bind(addr: &str) -> io::Result<Transport> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        Ok(Transport {
            listener,
            local_addr,
            peers: Vec::new(),
            outbound: Vec::new(),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn set_peers(&mut self, peers: Vec<String>) {
        self.outbound = peers.iter().map(|_| None).collect();
        self.peers = peers;
    }

    /// Spawn the accept loop; each inbound connection gets a reader thread that
    /// forwards decoded messages as [`Event::Wire`].
    pub fn start_accept(&self, tx: Sender<Event>) -> io::Result<()> {
        let listener = self.listener.try_clone()?;
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let tx = tx.clone();
                        thread::spawn(move || reader_loop(stream, tx));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }

    /// Send `msg` to every peer, connecting on demand. Best-effort: a peer that
    /// is down simply misses this message and reconnects on a later broadcast.
    pub fn broadcast(&mut self, msg: &WireMsg) {
        for i in 0..self.peers.len() {
            if self.outbound[i].is_none() {
                self.outbound[i] = TcpStream::connect(&self.peers[i]).ok();
            }
            if let Some(stream) = &mut self.outbound[i] {
                if write_frame(stream, msg).is_err() {
                    self.outbound[i] = None; // drop; reconnect next time
                }
            }
        }
    }
}

fn reader_loop(mut stream: TcpStream, tx: Sender<Event>) {
    // Ends when the peer closes/sends garbage or the node loop is gone.
    while let Ok(msg) = read_frame::<_, WireMsg>(&mut stream) {
        if tx.send(Event::Wire(msg)).is_err() {
            break;
        }
    }
}
