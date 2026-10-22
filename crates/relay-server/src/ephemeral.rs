//! Ephemeral events between relays. They are never stored, so nothing else
//! notices one arriving twice: from a client and again from a peer that
//! forwarded it, or back from a peer it was forwarded to. `Seen` remembers the
//! ids of the last two minutes, so each is delivered once and a forwarded one
//! cannot circle between relays.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an id is remembered: far longer than any relay-to-relay hop.
const WINDOW: Duration = Duration::from_secs(120);
/// At most this many ids (about 6 MB); the oldest go first past it.
const CAP: usize = 100_000;

#[derive(Default)]
pub struct Seen {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    ids: HashSet<[u8; 32]>,
    order: VecDeque<([u8; 32], Instant)>,
}

impl Seen {
    /// True the first time `id` is offered within the window; false after.
    pub fn first(&self, id: &[u8; 32], now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap();
        let Inner { ids, order } = &mut *g;
        while let Some(&(old, at)) = order.front() {
            if now.duration_since(at) < WINDOW && order.len() < CAP {
                break;
            }
            order.pop_front();
            ids.remove(&old);
        }
        if !ids.insert(*id) {
            return false;
        }
        order.push_back((*id, now));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn once_per_window() {
        let s = Seen::default();
        let t = Instant::now();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(s.first(&a, t));
        assert!(!s.first(&a, t + Duration::from_secs(1)), "a repeat");
        assert!(s.first(&b, t + Duration::from_secs(1)));
        assert!(!s.first(&a, t + Duration::from_secs(119)), "still remembered");
        assert!(s.first(&a, t + Duration::from_secs(121)), "forgotten after the window");
    }

    #[test]
    fn bounded() {
        let s = Seen::default();
        let t = Instant::now();
        for i in 0..(CAP as u32 + 10) {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_le_bytes());
            assert!(s.first(&id, t));
        }
        let g = s.inner.lock().unwrap();
        assert!(g.order.len() <= CAP && g.ids.len() == g.order.len());
    }
}
