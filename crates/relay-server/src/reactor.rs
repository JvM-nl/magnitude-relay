//! Reactors: one thread per core, each running its own single-threaded runtime.
//!
//! A connection lives on one reactor for its whole life. Parsing, signature
//! checks, queries and replies all happen on that core, so load spreads across
//! cores with no handoffs and no locks on the request path. Each reactor keeps
//! its own live-subscription index and receives every committed batch from the
//! writer (see `ingest.rs`) to fan out to its own connections.

use crate::config::Config;
use crate::ingest::{ReactorMsg, WriteReq};
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
use tokio::net::{TcpListener, TcpSocket, TcpStream};
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
    pub stats: Stats,
}

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU64,
    pub connections_total: AtomicU64,
    pub messages_in: AtomicU64,
    pub events_out: AtomicU64,
}

struct IpState {
    conns: u32,
    /// Token bucket for EVENTs: tokens (scaled by 1000 for sub-token refill) and last refill.
    tokens: u64,
    last: Instant,
}

impl Shared {
    pub fn new(cfg: Config, scfg: SessionCfg, store: Store, writer: SyncSender<WriteReq>) -> Shared {
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
            stats: Stats::default(),
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

/// Binds the listener for one reactor. On Linux every reactor binds the same
/// port with SO_REUSEPORT and the kernel spreads connections across them.
pub fn listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let s = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    s.set_reuseaddr(true)?;
    #[cfg(target_os = "linux")]
    s.set_reuseport(true)?;
    s.set_nodelay(true)?;
    s.bind(addr)?;
    let l = s.listen(4096)?;
    l.into_std()
}

/// Runs reactor `idx` on the current thread until the process exits.
pub fn run(idx: usize, shared: Arc<Shared>, listener: Option<std::net::TcpListener>, rx: mpsc::UnboundedReceiver<ReactorMsg>) {
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
        }));
        tokio::task::spawn_local(fanout(rx, st.clone(), shared.clone()));
        let Some(l) = listener else {
            // No listener of its own (non-Linux): this reactor only fans out.
            std::future::pending::<()>().await;
            return;
        };
        l.set_nonblocking(true).expect("nonblocking listener");
        let l = TcpListener::from_std(l).expect("listener");
        loop {
            match l.accept().await {
                Ok((s, peer)) => {
                    let _ = s.set_nodelay(true);
                    tokio::task::spawn_local(connection(s, peer, st.clone(), shared.clone()));
                }
                Err(e) => {
                    // Out of descriptors and the like: back off instead of spinning.
                    eprintln!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });
}

/// Delivers OK replies and live events from each committed batch.
async fn fanout(mut rx: mpsc::UnboundedReceiver<ReactorMsg>, st: Rc<RefCell<Reactor>>, shared: Arc<Shared>) {
    let mut targets = Vec::new();
    let mut json = Vec::new();
    let limit = shared.cfg.limits.outbound_buffer_bytes;
    while let Some(msg) = rx.recv().await {
        let mut guard = st.borrow_mut();
        let r = &mut *guard;
        let (events, gen): (&[Arc<[u8]>], u64) = match &msg {
            ReactorMsg::Committed(c) => {
                for reply in &c.replies[r.idx] {
                    if let Some(o) = r.conns.get(&reply.conn) {
                        session::ok_reply(&mut WsOut { buf: &mut o.buf.borrow_mut() }, reply);
                        o.notify.notify_one();
                    }
                }
                (&c.events, c.gen)
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
                    shared.stats.events_out.fetch_add(1, Ordering::Relaxed);
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
    if !shared.admit(ip) {
        let mut out = Vec::new();
        ws::write_close(&mut out, 1008, "too many connections from your address");
        let _ = s.write_all(&out).await;
        return;
    }
    shared.stats.connections.fetch_add(1, Ordering::Relaxed);
    shared.stats.connections_total.fetch_add(1, Ordering::Relaxed);
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
    shared.stats.connections.fetch_sub(1, Ordering::Relaxed);
}

#[allow(clippy::too_many_arguments)]
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
    let broadcast = |m: ReactorMsg| shared.broadcast(m);
    let allow_event = || shared.take_event(ip);
    loop {
        // Decode and answer everything buffered.
        let mut off = 0;
        let mut closing = false;
        loop {
            let d = match dec.decode(&mut buf[off..]) {
                Ok(d) => d,
                Err(e) => {
                    ws::write_close(&mut out.buf.borrow_mut(), e.close_code(), e.reason());
                    closing = true;
                    break;
                }
            };
            off += d.consumed;
            match d.event {
                Some(Event::Text(t)) => {
                    shared.stats.messages_in.fetch_add(1, Ordering::Relaxed);
                    let mut guard = st.borrow_mut();
                    let r = &mut *guard;
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
                    closing = true;
                    break;
                }
                None => break,
            }
        }
        buf.drain(..off);

        // Flush (taking the buffer, so fan-out keeps appending to a fresh one).
        if out.overflow.get() {
            ws::write_close(&mut out.buf.borrow_mut(), 1008, "too slow: messages were piling up");
            closing = true;
        }
        if !out.buf.borrow().is_empty() {
            std::mem::swap(&mut wbuf, &mut *out.buf.borrow_mut());
            s.write_all(&wbuf).await?;
            wbuf.clear();
            if wbuf.capacity() > 1 << 20 {
                wbuf = Vec::new();
            }
        }
        if closing {
            return Ok(());
        }

        // Wait for input, queued output, or the idle timer.
        let idle_at = last_rx + if pinged { IDLE_PING * 2 } else { IDLE_PING };
        tokio::select! {
            r = s.readable() => {
                r?;
                let want = dec.needed().saturating_sub(buf.len()).max(16 * 1024);
                let len = buf.len();
                buf.resize(len + want, 0);
                match s.try_read(&mut buf[len..]) {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        buf.truncate(len + n);
                        last_rx = Instant::now();
                        pinged = false;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => buf.truncate(len),
                    Err(e) => return Err(e),
                }
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
    if req.method == "OPTIONS" {
        write_response(&mut out, 204, "No Content", "text/plain", &cors, b"", true);
    } else if req.accepts("application/nostr+json") {
        write_response(&mut out, 200, "OK", "application/nostr+json", &cors, shared.nip11.as_bytes(), true);
    } else {
        let body = format!("{}\n\nThis is a Nostr relay. Connect to it with a Nostr client such as Vector.\n", shared.cfg.info.name);
        write_response(&mut out, 200, "OK", "text/plain; charset=utf-8", &cors, body.as_bytes(), true);
    }
    s.write_all(&out).await?;
    s.shutdown().await
}
