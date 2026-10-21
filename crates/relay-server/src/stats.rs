//! `/stats` (JSON) and `/metrics` (Prometheus text): the counters plus the
//! store's shape, rendered by hand.

use crate::config::json_str;
use crate::reactor::Shared;
use std::fmt::Write;
use std::sync::atomic::Ordering;

struct StoreShape {
    events: u64,
    dead: u64,
    index_keys: u64,
    index_mem_bytes: u64,
    segment_bytes: u64,
    segments: usize,
}

fn shape(shared: &Shared) -> StoreShape {
    let v = shared.store.snapshot();
    StoreShape {
        events: v.count,
        dead: v.dead_count(),
        index_keys: v.index_keys(),
        index_mem_bytes: v.index_bytes(),
        segment_bytes: v.segment_bytes(),
        segments: v.runs().iter().filter(|r| matches!(r, relay_store::version::Run::Disk(_))).count(),
    }
}

pub fn json(shared: &Shared) -> String {
    let t = shared.metrics.totals();
    let st = shape(shared);
    let mut o = String::with_capacity(1024);
    let _ = write!(
        o,
        "{{\"software\":\"{}\",\"version\":\"{}\",\"uptime_secs\":{},\"connections_open\":{}",
        crate::brand::NAME,
        crate::brand::VERSION,
        shared.metrics.uptime_secs(),
        shared.metrics.open.load(Ordering::Relaxed)
    );
    for (k, v) in t.fields() {
        let _ = write!(o, ",\"{k}\":{v}");
    }
    let _ = write!(
        o,
        ",\"store\":{{\"events\":{},\"live\":{},\"dead\":{},\"index_keys\":{},\"index_memory_bytes\":{},\"index_segment_bytes\":{},\"segments\":{}}}",
        st.events,
        st.events - st.dead,
        st.dead,
        st.index_keys,
        st.index_mem_bytes,
        st.segment_bytes,
        st.segments
    );
    // One object per [[sync]] entry: which relay, which way, which events, then its counters.
    o.push_str(",\"sync\":[");
    for (i, s) in shared.sync.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(o, "{{\"url\":{},\"direction\":\"{}\",\"filter\":{}", json_str(&s.url), s.direction, json_str(&s.filter));
        for (k, v) in s.fields() {
            let _ = write!(o, ",\"{k}\":{v}");
        }
        o.push('}');
    }
    o.push_str("]}");
    o
}

pub fn prometheus(shared: &Shared) -> String {
    let t = shared.metrics.totals();
    let st = shape(shared);
    let mut o = String::with_capacity(2048);
    let mut gauge = |name: &str, v: u64| {
        let _ = writeln!(o, "# TYPE relay_{name} gauge\nrelay_{name} {v}");
    };
    gauge("uptime_seconds", shared.metrics.uptime_secs());
    gauge("connections_open", shared.metrics.open.load(Ordering::Relaxed));
    gauge("store_events", st.events);
    gauge("store_dead", st.dead);
    gauge("store_index_keys", st.index_keys);
    gauge("store_index_memory_bytes", st.index_mem_bytes);
    gauge("store_index_segment_bytes", st.segment_bytes);
    gauge("store_segments", st.segments as u64);
    for (k, v) in t.fields() {
        let _ = writeln!(o, "# TYPE relay_{k} counter\nrelay_{k} {v}");
    }
    // Labelled by the other relay's URL; a label value escapes `\`, `"` and newlines.
    if let Some(first) = shared.sync.first() {
        for (k, _) in first.fields() {
            let kind = if matches!(k, "connected" | "last_reconcile_at" | "last_reconcile_ms" | "last_need" | "last_have") { "gauge" } else { "counter" };
            let _ = writeln!(o, "# TYPE relay_sync_{k} {kind}");
            for s in &shared.sync {
                let url = s.url.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
                let v = s.fields().into_iter().find(|(n, _)| *n == k).map_or(0, |(_, v)| v);
                let _ = writeln!(o, "relay_sync_{k}{{url=\"{url}\",direction=\"{}\"}} {v}", s.direction);
            }
        }
    }
    o
}
