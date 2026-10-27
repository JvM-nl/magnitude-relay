//! `/stats` (JSON) and `/metrics` (Prometheus text): the counters, the
//! store's shape, and the host's health with any warnings, rendered by hand.

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
        "{{\"software\":\"{}\",\"version\":\"{}\",\"build\":\"{}\",\"name\":{},\"uptime_secs\":{},\"connections_open\":{},\"neg_items_held\":{}",
        crate::brand::NAME,
        crate::brand::VERSION,
        crate::brand::BUILD,
        json_str(&shared.cfg.info.name),
        shared.metrics.uptime_secs(),
        shared.metrics.open.load(Ordering::Relaxed),
        crate::session::NEG_ITEMS.load(Ordering::Relaxed)
    );
    for (k, v) in t.fields() {
        let _ = write!(o, ",\"{k}\":{v}");
    }
    let _ = write!(
        o,
        ",\"store\":{{\"events\":{},\"live\":{},\"dead\":{},\"index_keys\":{},\"index_memory_bytes\":{},\"index_segment_bytes\":{},\"segments\":{},\"damaged_reads\":{}}}",
        st.events,
        st.events - st.dead,
        st.dead,
        st.index_keys,
        st.index_mem_bytes,
        st.segment_bytes,
        st.segments,
        relay_store::log::DAMAGED_READS.load(Ordering::Relaxed)
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
    o.push(']');
    // Bulk passes with other relays, both ways: the ones this relay runs
    // ([[sync]]) and the ones its peers run against it ([[peer]]). `since` is
    // when the running (or last) pass began, `last_at` when the last one ended
    // (or was last heard from), `moved` the events it copied either way;
    // `window_secs` how far back a pass of ours reaches (0: every event, and
    // always 0 for a peer's, whose reach only the peer knows).
    let now = crate::ingest::now();
    let g = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
    let mut links = Vec::new();
    for s in &shared.sync {
        let since = g(&s.pass_since);
        links.push((&s.name, "running", since > 0, since, g(&s.pass_window), g(&s.last_reconcile_at), g(&s.last_need) + g(&s.last_have)));
    }
    for l in &shared.links {
        links.push((&l.name, "serving", l.active(now), g(&l.since), 0, g(&l.last), g(&l.moved)));
    }
    o.push_str(",\"links\":[");
    for (i, (name, role, active, since, window, last_at, moved)) in links.into_iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(
            o,
            "{{\"name\":{},\"role\":\"{role}\",\"active\":{active},\"since\":{since},\"window_secs\":{window},\"last_at\":{last_at},\"moved\":{moved}}}",
            json_str(name)
        );
    }
    o.push(']');
    // The host, the store's durability, and what deserves attention.
    let damaged = relay_store::log::DAMAGED_READS.load(Ordering::Relaxed);
    let h = crate::health::host(&shared.cfg.store.data);
    let num = |v: Option<u64>| v.map_or("null".to_string(), |v| v.to_string());
    let psi = |p: Option<crate::health::Pressure>| {
        p.map_or("null".to_string(), |p| format!("{{\"some_avg10\":{:.2},\"some_avg60\":{:.2},\"full_avg10\":{:.2},\"full_avg60\":{:.2}}}", p.some10, p.some60, p.full10, p.full60))
    };
    let _ = write!(
        o,
        ",\"host\":{{\"disk_total_bytes\":{},\"disk_available_bytes\":{},\"memory_total_bytes\":{},\"memory_available_bytes\":{},\"open_files\":{},\"open_files_limit\":{},\"pressure\":{{\"cpu\":{},\"memory\":{},\"io\":{}}}}}",
        num(h.disk_total),
        num(h.disk_available),
        num(h.memory_total),
        num(h.memory_available),
        num(h.open_files),
        num(h.open_files_limit),
        psi(h.cpu),
        psi(h.memory),
        psi(h.io)
    );
    let a = |x: &std::sync::atomic::AtomicU64| x.load(Ordering::Relaxed);
    use crate::health::*;
    let _ = write!(
        o,
        ",\"durability\":{{\"syncs\":{},\"sync_ms_total\":{},\"slow_syncs\":{},\"slowest_sync_ms\":{},\"failed_syncs\":{},\"failed_writes\":{},\"no_space_refusals\":{}}}",
        a(&SYNCS),
        a(&SYNC_MICROS) / 1000,
        a(&SYNCS_SLOW),
        a(&SYNC_SLOWEST_MICROS) / 1000,
        a(&SYNCS_FAILED),
        a(&WRITES_FAILED),
        a(&WRITES_NO_SPACE)
    );
    o.push_str(",\"warnings\":[");
    for (i, w) in warnings(&h, damaged).iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let _ = write!(o, "{{\"level\":\"{}\",\"what\":\"{}\",\"message\":{}}}", w.level.name(), w.what, json_str(&w.message));
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
    gauge("neg_items_held", crate::session::NEG_ITEMS.load(Ordering::Relaxed));
    gauge("store_events", st.events);
    gauge("store_dead", st.dead);
    gauge("store_index_keys", st.index_keys);
    gauge("store_index_memory_bytes", st.index_mem_bytes);
    gauge("store_index_segment_bytes", st.segment_bytes);
    gauge("store_segments", st.segments as u64);
    let damaged = relay_store::log::DAMAGED_READS.load(Ordering::Relaxed);
    gauge("store_damaged_reads", damaged);
    // The host: an alerting system can watch these, or just `relay_warnings`.
    let h = crate::health::host(&shared.cfg.store.data);
    for (name, v) in [
        ("host_disk_total_bytes", h.disk_total),
        ("host_disk_available_bytes", h.disk_available),
        ("host_memory_total_bytes", h.memory_total),
        ("host_memory_available_bytes", h.memory_available),
        ("open_files", h.open_files),
        ("open_files_limit", h.open_files_limit),
    ] {
        if let Some(v) = v {
            gauge(name, v);
        }
    }
    {
        let mut f = |name: &str, v: f64| {
            let _ = writeln!(o, "# TYPE relay_{name} gauge\nrelay_{name} {v}");
        };
        for (res, p) in [("cpu", h.cpu), ("memory", h.memory), ("io", h.io)] {
            if let Some(p) = p {
                f(&format!("host_pressure_{res}_some_avg60"), p.some60);
                f(&format!("host_pressure_{res}_full_avg60"), p.full60);
            }
        }
    }
    {
        use crate::health::*;
        let a = |x: &std::sync::atomic::AtomicU64| x.load(Ordering::Relaxed);
        for (name, v) in [
            ("syncs_total", a(&SYNCS)),
            ("sync_microseconds_total", a(&SYNC_MICROS)),
            ("syncs_slow_total", a(&SYNCS_SLOW)),
            ("syncs_failed_total", a(&SYNCS_FAILED)),
            ("writes_failed_total", a(&WRITES_FAILED)),
            ("writes_no_space_total", a(&WRITES_NO_SPACE)),
        ] {
            let _ = writeln!(o, "# TYPE relay_{name} counter\nrelay_{name} {v}");
        }
        let ws = warnings(&h, damaged);
        let _ = writeln!(o, "# TYPE relay_warnings gauge");
        for level in [Level::Warning, Level::Critical] {
            let _ = writeln!(o, "relay_warnings{{level=\"{}\"}} {}", level.name(), ws.iter().filter(|w| w.level == level).count());
        }
    }
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
