//! Reactors: one thread per core, each running its own single-threaded runtime.
//!
//! A connection lives on one reactor for its whole life. Parsing, signature
//! checks, queries and replies all happen on that core, so load spreads across
//! cores with no handoffs and no locks on the request path. Each reactor keeps
//! its own live-subscription index and receives every committed batch from the
//! writer (see `ingest.rs`) to fan out to its own connections.

use crate::config::Config;
use crate::ingest::{ReactorMsg, WriteReq};
use crate::metrics::{self, Metrics};
use crate::session::{self, Ctx, Outbox, Session, SessionCfg};
use crate::subs::{ConnId, FxMap, SubIndex};
use relay_net::conn::{server_handshake, Handshake, OwnedRequest};
use relay_net::http::write_response;
use relay_net::ws::{self, Decoder, Event};
use relay_proto::{EventParser, Record};
use relay_store::{Store, Version};
use std::cell::{Cell, RefCell};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{mpsc, Notify};

/// A client silent this long gets a ping; silent twice as long, it is dropped.
const IDLE_PING: Duration = Duration::from_secs(60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEAD: usize = 8 * 1024;

/// State every reactor shares. Read-mostly; the only lock is the per-IP table,
/// touched on connect, disconnect and EVENT.
pub struct Shared {
    pub cfg: Config,
    pub scfg: SessionCfg,
    pub store: Store,
    pub writer: SyncSender<WriteReq>,
    pub reactors: OnceLock<Vec<mpsc::UnboundedSender<ReactorMsg>>>,
    pub nip11: String,
    pub next_conn: AtomicU64,
    ips: Mutex<FxMap<IpAddr, IpState>>,
    pub metrics: Metrics,
}

struct IpState {
    conns: u32,
    /// Token bucket for EVENTs: tokens (scaled by 1000 for sub-token refill) and last refill.
    tokens: u64,
    last: Instant,
}

impl Shared {
    pub fn new(cfg: Config, scfg: SessionCfg, store: Store, writer: SyncSender<WriteReq>, reactors: usize) -> Shared {
        let nip11 = cfg.nip11_json();
        Shared {
            cfg,
            scfg,
            store,
            writer,
            reactors: OnceLock::new(),
            nip11,
            next_conn: AtomicU64::new(1),
            ips: Mutex::new(FxMap::default()),
            metrics: Metrics::new(reactors),
        }
    }

    /// Counts a connection from `ip`, unless that IP is at its limit.
    fn admit(&self, ip: IpAddr) -> bool {
        let max = self.cfg.limits.max_connections_per_ip;
        let mut ips = self.ips.lock().unwrap();
        let burst = u64::from(self.cfg.limits.events_per_minute_per_ip) * 1000;
        let e = ips.entry(ip).or_insert(IpState { conns: 0, tokens: burst, last: Instant::now() });
        if max != 0 && e.conns >= max {
            return false;
        }
        e.conns += 1;
        true
    }

    fn release(&self, ip: IpAddr) {
        let mut ips = self.ips.lock().unwrap();
        if let Some(e) = ips.get_mut(&ip) {
            e.conns = e.conns.saturating_sub(1);
            if e.conns == 0 {
                ips.remove(&ip);
            }
        }
    }

    /// Takes one EVENT token for `ip` (a bucket holding a minute's allowance,
    /// refilled continuously).
    fn take_event(&self, ip: IpAddr) -> bool {
        let per_min = u64::from(self.cfg.limits.events_per_minute_per_ip);
        if per_min == 0 {
            return true;
        }
        let mut ips = self.ips.lock().unwrap();
        let Some(e) = ips.get_mut(&ip) else { return true };
        let now = Instant::now();
        let refill = now.duration_since(e.last).as_millis() as u64 * per_min / 60;
        e.tokens = (e.tokens + refill).min(per_min * 1000);
        e.last = now;
        if e.tokens >= 1000 {
            e.tokens -= 1000;
            true
        } else {
            false
        }
    }

    pub fn broadcast(&self, msg: ReactorMsg) {
        for tx in self.reactors.get().expect("reactors registered") {
            let _ = tx.send(msg.clone());
        }
    }
}

/// One connection's outgoing bytes, filled by its own task and by fan-out.
struct ConnOut {
    buf: RefCell<Vec<u8>>,
    notify: Notify,
    /// Set when the client fell too far behind; its task closes it.
    overflow: Cell<bool>,
}

struct Reactor {
    idx: usize,
    snap: Arc<Version>,
    subs: SubIndex,
    conns: FxMap<ConnId, Rc<ConnOut>>,
    parser: EventParser,
    rec: Vec<u8>,
    /// Read buffer shared by every connection on this reactor.
    scratch: Vec<u8>,
    /// Live batches relayed but not yet published, oldest first.
    pending: std::collections::VecDeque<Arc<crate::ingest::LiveBatch>>,
}

/// Frames each reply as a WebSocket text message, built in place.
struct WsOut<'a> {
    buf: &'a mut Vec<u8>,
}

impl Outbox for WsOut<'_> {
    #[inline]
    fn text(&mut self, f: &mut dyn FnMut(&mut Vec<u8>)) {
        let mark = ws::begin_text(self.buf);
        f(self.buf);
        ws::finish_text(self.buf, mark);
    }
}

/// Binds the relay's one listener.
pub fn listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let s = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    s.set_reuseaddr(true)?;
    s.set_nodelay(true)?;
    s.bind(addr)?;
    let l = s.listen(4096)?;
    let l = l.into_std()?;
    // The acceptor thread blocks in accept(); connections become non-blocking
    // when their reactor adopts them.
    l.set_nonblocking(false)?;
    Ok(l)
}

/// Accepts connections and deals them to reactors round-robin. SO_REUSEPORT
/// hashing leaves reactors idle when connections are few (eight benchmark
/// clients can land 3-3-1-1 or worse), and signature checks are per core, so an
/// idle reactor is lost throughput; dealing in turn places them exactly.
pub fn accept_loop(l: std::net::TcpListener, conns: Vec<mpsc::UnboundedSender<(std::net::TcpStream, SocketAddr)>>) {
    let mut next = 0usize;
    loop {
        match l.accept() {
            Ok((s, peer)) => {
                let _ = s.set_nodelay(true);
                if s.set_nonblocking(true).is_ok() {
                    let _ = conns[next % conns.len()].send((s, peer));
                    next = next.wrapping_add(1);
                }
            }
            Err(e) => {
                // Out of descriptors and the like: back off instead of spinning.
                eprintln!("accept failed: {e}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Runs reactor `idx` on the current thread until the process exits.
pub fn run(
    idx: usize,
    shared: Arc<Shared>,
    mut conns: mpsc::UnboundedReceiver<(std::net::TcpStream, SocketAddr)>,
    rx: mpsc::UnboundedReceiver<ReactorMsg>,
) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async move {
        let st = Rc::new(RefCell::new(Reactor {
            idx,
            snap: shared.store.snapshot(),
            subs: SubIndex::default(),
            conns: FxMap::default(),
            parser: EventParser::new(),
            rec: Vec::new(),
            scratch: vec![0; READ_CHUNK],
            pending: std::collections::VecDeque::new(),
        }));
        tokio::task::spawn_local(fanout(rx, st.clone(), shared.clone()));
        while let Some((s, peer)) = conns.recv().await {
            match TcpStream::from_std(s) {
                Ok(s) => {
                    tokio::task::spawn_local(connection(s, peer, st.clone(), shared.clone()));
                }
                Err(e) => eprintln!("cannot adopt connection: {e}"),
            }
        }
    });
}

/// Delivers OK replies and live events from each committed batch.
async fn fanout(mut rx: mpsc::UnboundedReceiver<ReactorMsg>, st: Rc<RefCell<Reactor>>, shared: Arc<Shared>) {
    let mut targets = Vec::new();
    let mut json = Vec::new();
    let limit = shared.cfg.limits.outbound_buffer_bytes;
    // RELAY_DEBUG_WRITER: how long live batches take to reach this reactor.
    let debug = crate::ingest::debug();
    let (mut d_n, mut d_handoff, mut d_since_read, mut d_max) = (0u64, 0f64, 0f64, 0f64);
    let mut d_last = std::time::Instant::now();
    while let Some(msg) = rx.recv().await {
        let mut guard = st.borrow_mut();
        let r = &mut *guard;
        if debug {
            if let ReactorMsg::Live(b) = &msg {
                let h = b.sent.elapsed().as_secs_f64();
                d_n += 1;
                d_handoff += h;
                d_max = d_max.max(h);
                d_since_read += b.received.elapsed().as_secs_f64();
            }
            if d_last.elapsed().as_secs() >= 1 && d_n > 0 {
                eprintln!(
                    "reactor {}: {d_n} live batches, handoff {:.0} us avg ({:.0} max), EVENT read to fan-out {:.0} us avg",
                    r.idx,
                    d_handoff * 1e6 / d_n as f64,
                    d_max * 1e6,
                    d_since_read * 1e6 / d_n as f64
                );
                (d_n, d_handoff, d_since_read, d_max) = (0, 0.0, 0.0, 0.0);
                d_last = std::time::Instant::now();
            }
        }
        let (events, gen): (&[Arc<[u8]>], u64) = match &msg {
            ReactorMsg::Live(b) => {
                // Kept until published: a REQ answered from an older snapshot in
                // the meantime replays it (see Session::on_req).
                r.pending.push_back(b.clone());
                (&b.events, b.gen)
            }
            ReactorMsg::Replies(c) => {
                while r.pending.front().is_some_and(|p| p.gen <= c.gen) {
                    r.pending.pop_front();
                }
                let m = shared.metrics.of(r.idx);
                for reply in &c.replies[r.idx] {
                    match reply.outcome {
                        Some(relay_store::Outcome::Stored(_)) => metrics::inc(&m.events_stored),
                        Some(relay_store::Outcome::Duplicate) => metrics::inc(&m.events_duplicate),
                        _ => metrics::inc(&m.events_refused),
                    }
                    if let Some(o) = r.conns.get(&reply.conn) {
                        session::ok_reply(&mut WsOut { buf: &mut o.buf.borrow_mut() }, reply);
                        o.notify.notify_one();
                    }
                }
                (&[], 0)
            }
            ReactorMsg::Ephemeral(e) => (std::slice::from_ref(e), u64::MAX),
        };
        for rec in events {
            targets.clear();
            r.subs.matches(Record(rec), gen, &mut targets);
            if targets.is_empty() {
                continue;
            }
            // Encoded once, whatever the number of subscribers.
            json.clear();
            Record(rec).write_json(&mut json);
            for (conn, sub) in &targets {
                let Some(o) = r.conns.get(conn) else { continue };
                let mut b = o.buf.borrow_mut();
                if b.len() > limit {
                    o.overflow.set(true);
                } else {
                    session::event_msg_json(&mut WsOut { buf: &mut b }, sub, &json);
                    let m = shared.metrics.of(r.idx);
                    metrics::inc(&m.events_out);
                    metrics::inc(&m.events_live);
                }
                drop(b);
                o.notify.notify_one();
            }
        }
    }
}

fn client_ip(req: &OwnedRequest, peer: SocketAddr, header: &str) -> IpAddr {
    let fallback = peer.ip().to_canonical();
    if header.is_empty() {
        return fallback;
    }
    // Right-most entry of the last header line: the one our own proxy appended.
    let Some((_, v)) = req.headers.iter().rev().find(|(n, _)| n == header) else { return fallback };
    let last = v.rsplit(|&b| b == b',').next().unwrap_or(&[]);
    std::str::from_utf8(last).ok().and_then(|s| s.trim().parse::<IpAddr>().ok()).map_or(fallback, |ip| ip.to_canonical())
}

async fn connection(mut s: TcpStream, peer: SocketAddr, st: Rc<RefCell<Reactor>>, shared: Arc<Shared>) {
    let mut buf = Vec::with_capacity(4096);
    let req = match tokio::time::timeout(HANDSHAKE_TIMEOUT, server_handshake(&mut s, &mut buf, MAX_HEAD)).await {
        Ok(Ok(Handshake::Upgraded(req))) => req,
        Ok(Ok(Handshake::PlainHttp(req))) => {
            let _ = plain_http(&mut s, &req, &shared).await;
            return;
        }
        _ => return,
    };
    let ip = client_ip(&req, peer, &shared.cfg.relay.real_ip_header);
    let idx = st.borrow().idx;
    if !shared.admit(ip) {
        metrics::inc(&shared.metrics.of(idx).connections_refused);
        let mut out = Vec::new();
        ws::write_close(&mut out, 1008, "too many connections from your address");
        let _ = s.write_all(&out).await;
        return;
    }
    shared.metrics.open.fetch_add(1, Ordering::Relaxed);
    metrics::inc(&shared.metrics.of(idx).connections_total);
    let conn = shared.next_conn.fetch_add(1, Ordering::Relaxed);
    let out = Rc::new(ConnOut { buf: RefCell::new(Vec::new()), notify: Notify::new(), overflow: Cell::new(false) });
    st.borrow_mut().conns.insert(conn, out.clone());

    let _ = serve(&mut s, &mut buf, conn, ip, &out, &st, &shared).await;

    {
        let mut r = st.borrow_mut();
        r.subs.remove_conn(conn);
        r.conns.remove(&conn);
    }
    shared.release(ip);
    shared.metrics.open.fetch_sub(1, Ordering::Relaxed);
}

/// Bytes read per readiness event, into the reactor's shared scratch buffer.
const READ_CHUNK: usize = 64 * 1024;

/// Work one connection may do before letting the reactor's other tasks run.
/// A burst of 64 EVENTs is ~4 ms of signature checks; without a budget, live
/// deliveries and REQs on the same core would wait behind all of it.
const TURN_BUDGET: Duration = Duration::from_micros(300);

/// What one pass over a buffer did.
struct Pass {
    /// Bytes used (a trailing partial frame, or frames left for the next turn, remain).
    used: usize,
    closing: bool,
    /// Stopped on the time budget with whole frames still unprocessed.
    more: bool,
}

/// Decodes and answers whole frames in `data` until the buffer or the turn's
/// time budget runs out.
fn process(data: &mut [u8], dec: &mut Decoder, session: &mut Session, out: &ConnOut, st: &RefCell<Reactor>, shared: &Shared, ip: IpAddr) -> Pass {
    let broadcast = |m: ReactorMsg| shared.broadcast(m);
    let allow_event = || shared.take_event(ip);
    let started = Instant::now();
    let mut off = 0;
    loop {
        if off > 0 && started.elapsed() >= TURN_BUDGET {
            return Pass { used: off, closing: false, more: true };
        }
        let d = match dec.decode(&mut data[off..]) {
            Ok(d) => d,
            Err(e) => {
                ws::write_close(&mut out.buf.borrow_mut(), e.close_code(), e.reason());
                return Pass { used: off, closing: true, more: false };
            }
        };
        off += d.consumed;
        match d.event {
            Some(Event::Text(t)) => {
                let mut guard = st.borrow_mut();
                let r = &mut *guard;
                let m = shared.metrics.of(r.idx);
                metrics::inc(&m.messages_in);
                shared.store.refresh(&mut r.snap);
                let mut cx = Ctx {
                    cfg: &shared.scfg,
                    store: &shared.store,
                    snap: &mut r.snap,
                    subs: &mut r.subs,
                    writer: &shared.writer,
                    reactor: r.idx,
                    broadcast: &broadcast,
                    allow_event: &allow_event,
                    parser: &mut r.parser,
                    rec: &mut r.rec,
                    now: crate::ingest::now(),
                    m,
                    pending: &r.pending,
                };
                session.on_text(t, &mut cx, &mut WsOut { buf: &mut out.buf.borrow_mut() });
            }
            Some(Event::Binary(_)) => {
                session::notice(&mut WsOut { buf: &mut out.buf.borrow_mut() }, "error: binary messages are not supported");
            }
            Some(Event::Ping(p)) => ws::write_pong(&mut out.buf.borrow_mut(), p),
            Some(Event::Pong(_)) => {}
            Some(Event::Close(c)) => {
                let mut b = out.buf.borrow_mut();
                match c {
                    Some((code, _)) => ws::write_close(&mut b, code, ""),
                    None => ws::write_close_empty(&mut b),
                }
                return Pass { used: off, closing: true, more: false };
            }
            None => return Pass { used: off, closing: false, more: false },
        }
    }
}

/// Runs one WebSocket connection. Reads land in the reactor's shared scratch
/// buffer and are decoded in place; the connection keeps bytes of its own only
/// while a frame is split across reads, and frees them as soon as it is whole,
/// so an idle connection costs almost nothing.
async fn serve(
    s: &mut TcpStream,
    buf: &mut Vec<u8>,
    conn: ConnId,
    ip: IpAddr,
    out: &Rc<ConnOut>,
    st: &Rc<RefCell<Reactor>>,
    shared: &Arc<Shared>,
) -> io::Result<()> {
    let max = shared.cfg.limits.max_message_bytes;
    let mut dec = Decoder::server(max, max);
    let mut session = Session::new(conn);
    let mut wbuf = Vec::new();
    let mut last_rx = Instant::now();
    let mut pinged = false;
    // Frames that arrived with the handshake.
    let p = process(&mut buf[..], &mut dec, &mut session, out, st, shared, ip);
    buf.drain(..p.used);
    *buf = buf.to_vec();
    let (mut closing, mut more) = (p.closing, p.more);
    loop {
        // Flush (taking the buffer, so fan-out keeps appending to a fresh one).
        if out.overflow.get() {
            ws::write_close(&mut out.buf.borrow_mut(), 1008, "too slow: messages were piling up");
            metrics::inc(&shared.metrics.of(st.borrow().idx).slow_drops);
            closing = true;
        }
        if !out.buf.borrow().is_empty() {
            std::mem::swap(&mut wbuf, &mut *out.buf.borrow_mut());
            metrics::add(&shared.metrics.of(st.borrow().idx).bytes_out, wbuf.len() as u64);
            s.write_all(&wbuf).await?;
            wbuf.clear();
            // Idle connections keep no output buffer; a busy one keeps a modest one.
            if wbuf.capacity() > 64 * 1024 {
                wbuf = Vec::new();
            }
        }
        if closing {
            return Ok(());
        }
        if more {
            // Out of budget with frames left: let the reactor's other tasks run.
            tokio::task::yield_now().await;
            let p = process(&mut buf[..], &mut dec, &mut session, out, st, shared, ip);
            buf.drain(..p.used);
            (closing, more) = (p.closing, p.more);
            if buf.is_empty() && buf.capacity() > 0 {
                *buf = Vec::new();
            }
            continue;
        }

        // Wait for input, queued output, or the idle timer.
        let idle_at = last_rx + if pinged { IDLE_PING * 2 } else { IDLE_PING };
        tokio::select! {
            r = s.readable() => {
                r?;
                let mut scratch = std::mem::take(&mut st.borrow_mut().scratch);
                scratch.resize(READ_CHUNK, 0);
                let result = s.try_read(&mut scratch);
                match result {
                    Ok(0) => {
                        st.borrow_mut().scratch = scratch;
                        return Ok(());
                    }
                    Ok(n) => {
                        metrics::add(&shared.metrics.of(st.borrow().idx).bytes_in, n as u64);
                        last_rx = Instant::now();
                        pinged = false;
                        if buf.is_empty() {
                            // The common case: decode straight from the scratch buffer.
                            let p = process(&mut scratch[..n], &mut dec, &mut session, out, st, shared, ip);
                            buf.extend_from_slice(&scratch[p.used..n]);
                            (closing, more) = (p.closing, p.more);
                        } else {
                            buf.extend_from_slice(&scratch[..n]);
                            let p = process(&mut buf[..], &mut dec, &mut session, out, st, shared, ip);
                            buf.drain(..p.used);
                            (closing, more) = (p.closing, p.more);
                        }
                        if buf.is_empty() && buf.capacity() > 0 {
                            *buf = Vec::new();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        st.borrow_mut().scratch = scratch;
                        return Err(e);
                    }
                }
                st.borrow_mut().scratch = scratch;
            }
            _ = out.notify.notified() => {}
            _ = tokio::time::sleep_until(idle_at.into()) => {
                if pinged {
                    return Ok(());
                }
                ws::write_ping(&mut out.buf.borrow_mut(), b"");
                pinged = true;
            }
        }
    }
}

/// Plain HTTP: the NIP-11 document for `Accept: application/nostr+json`, a short
/// note otherwise.
async fn plain_http(s: &mut TcpStream, req: &OwnedRequest, shared: &Shared) -> io::Result<()> {
    let mut out = Vec::new();
    let cors = [
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Headers", "*"),
        ("Access-Control-Allow-Methods", "GET, OPTIONS"),
    ];
    let path = req.path.split('?').next().unwrap_or("");
    if req.method == "OPTIONS" {
        write_response(&mut out, 204, "No Content", "text/plain", &cors, b"", true);
    } else if path == "/dashboard" {
        // Same-origin with /stats, which is all it reads.
        write_response(&mut out, 200, "OK", "text/html; charset=utf-8", &[], include_str!("dashboard.html").as_bytes(), true);
    } else if path == "/stats" {
        write_response(&mut out, 200, "OK", "application/json", &cors, crate::stats::json(shared).as_bytes(), true);
    } else if path == "/metrics" {
        write_response(&mut out, 200, "OK", "text/plain; version=0.0.4", &[], crate::stats::prometheus(shared).as_bytes(), true);
    } else if req.accepts("application/nostr+json") {
        write_response(&mut out, 200, "OK", "application/nostr+json", &cors, shared.nip11.as_bytes(), true);
    } else {
        let body = format!("{}\n\nThis is a Nostr relay. Connect to it with a Nostr client such as Vector.\n", shared.cfg.info.name);
        write_response(&mut out, 200, "OK", "text/plain; charset=utf-8", &cors, body.as_bytes(), true);
    }
    s.write_all(&out).await?;
    s.shutdown().await
}
