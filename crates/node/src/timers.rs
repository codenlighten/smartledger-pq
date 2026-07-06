//! A single-threaded timer wheel. The consensus engine asks for a timeout via
//! an [`crate::Effect::ScheduleTimeout`]; we arm it here and deliver an
//! [`Event::Timeout`] when it elapses. Stale timeouts are harmless — the engine
//! ignores any that no longer match its current height/round.

use crate::event::Event;
use slc_consensus::TimeoutKind;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

struct Timer {
    deadline: Instant,
    height: u64,
    round: u64,
    kind: TimeoutKind,
}

// Ordered by *earliest* deadline so a max-heap wrapped in `Reverse` pops soonest.
impl PartialEq for Timer {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}
impl Eq for Timer {}
impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Timer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so the BinaryHeap (a max-heap) yields the nearest deadline.
        other.deadline.cmp(&self.deadline)
    }
}

enum Cmd {
    Schedule(Timer),
    Stop,
}

pub struct TimerService {
    cmd_tx: Sender<Cmd>,
}

impl TimerService {
    pub fn start(ev_tx: Sender<Event>) -> TimerService {
        let (cmd_tx, cmd_rx) = channel::<Cmd>();
        thread::spawn(move || {
            let mut heap: BinaryHeap<Timer> = BinaryHeap::new();
            loop {
                // Fire everything already due.
                let now = Instant::now();
                while heap.peek().is_some_and(|t| t.deadline <= now) {
                    let t = heap.pop().unwrap();
                    if ev_tx.send(Event::Timeout(t.height, t.round, t.kind)).is_err() {
                        return;
                    }
                }
                let wait = heap
                    .peek()
                    .map(|t| t.deadline.saturating_duration_since(Instant::now()))
                    .unwrap_or(Duration::from_secs(3600));
                match cmd_rx.recv_timeout(wait) {
                    Ok(Cmd::Schedule(t)) => heap.push(t),
                    Ok(Cmd::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
        });
        TimerService { cmd_tx }
    }

    pub fn schedule(&self, height: u64, round: u64, kind: TimeoutKind, delay: Duration) {
        let _ = self.cmd_tx.send(Cmd::Schedule(Timer {
            deadline: Instant::now() + delay,
            height,
            round,
            kind,
        }));
    }

    pub fn stop(&self) {
        let _ = self.cmd_tx.send(Cmd::Stop);
    }
}
