//! Notarization metering: count a node's client submissions and enforce the
//! licensed monthly volume. The count is per calendar-ish window (30 days),
//! persisted so a restart doesn't reset usage. Only *local* client submissions
//! (RPC) are metered — gossiped attestations from peers are not the licensee's
//! billable usage.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A 30-day window approximates "per month" without a calendar dependency.
const WINDOW_SECS: u64 = 30 * 24 * 3600;

#[derive(Serialize, Deserialize)]
struct Persisted {
    count: u64,
    window_start: u64,
}

/// Tracks notarizations in the current window against an optional cap.
pub struct Meter {
    cap: Option<u64>,
    count: u64,
    window_start: u64,
    path: Option<PathBuf>,
}

impl Meter {
    /// Create a meter with an optional `cap` (from the license) and optional
    /// persistence `path`, restoring prior usage if present.
    pub fn new(cap: Option<u64>, path: Option<PathBuf>, now: u64) -> Meter {
        let (count, window_start) = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Persisted>(&s).ok())
            .map(|p| (p.count, p.window_start))
            .unwrap_or((0, now));
        let mut m = Meter {
            cap,
            count,
            window_start,
            path,
        };
        m.roll(now);
        m
    }

    fn roll(&mut self, now: u64) {
        if now >= self.window_start.saturating_add(WINDOW_SECS) {
            self.window_start = now;
            self.count = 0;
        }
    }

    /// Attempt to record one notarization at `now`. Returns `true` if within the
    /// licensed volume (and increments), `false` if the cap is reached.
    pub fn try_record(&mut self, now: u64) -> bool {
        self.roll(now);
        if let Some(cap) = self.cap {
            if self.count >= cap {
                return false;
            }
        }
        self.count += 1;
        self.persist();
        true
    }

    /// `(count, cap, window_start, window_secs)`.
    pub fn status(&self) -> (u64, Option<u64>, u64, u64) {
        (self.count, self.cap, self.window_start, WINDOW_SECS)
    }

    fn persist(&self) {
        if let Some(p) = &self.path {
            let data = Persisted {
                count: self.count,
                window_start: self.window_start,
            };
            if let Ok(json) = serde_json::to_string(&data) {
                let _ = std::fs::write(p, json);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_cap_within_window() {
        let mut m = Meter::new(Some(2), None, 1000);
        assert!(m.try_record(1000));
        assert!(m.try_record(1001));
        assert!(!m.try_record(1002), "3rd exceeds cap of 2");
        assert_eq!(m.status().0, 2);
    }

    #[test]
    fn resets_after_window() {
        let mut m = Meter::new(Some(1), None, 1000);
        assert!(m.try_record(1000));
        assert!(!m.try_record(1001));
        // A month later, usage resets.
        assert!(m.try_record(1000 + WINDOW_SECS));
        assert_eq!(m.status().0, 1);
    }

    #[test]
    fn unmetered_when_no_cap() {
        let mut m = Meter::new(None, None, 0);
        for i in 0..1000 {
            assert!(m.try_record(i));
        }
    }

    #[test]
    fn persists_and_restores_usage() {
        let dir = std::env::temp_dir().join(format!("slc-meter-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("meter.json");
        {
            let mut m = Meter::new(Some(5), Some(path.clone()), 1000);
            assert!(m.try_record(1000));
            assert!(m.try_record(1001));
        }
        // A fresh meter (e.g. after restart) reloads the count.
        let m2 = Meter::new(Some(5), Some(path.clone()), 1002);
        assert_eq!(m2.status().0, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
