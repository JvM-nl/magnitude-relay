//! `serve`: start the relay. Also what running the binary with no arguments does.

use crate::config::{store_options, Config};
use crate::ingest::{self, Sink};
use crate::reactor::{self, Shared};
use crate::session::SessionCfg;
use relay_store::Store;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::Instant;
use tokio::sync::mpsc as tmpsc;

/// Events waiting for the writer before EVENTs are answered "busy". At group
/// commit rates this is well under a second of backlog.
const WRITE_QUEUE: usize = 65_536;

pub fn run(cfg: Config) -> Result<(), String> {
    let t = Instant::now();
    let (store, w) = Store::open(&cfg.store.data, store_options(&cfg)).map_err(|e| format!("{}: {e}", cfg.store.data.display()))?;
    let events = w.next_seq();
    let threads = if cfg.relay.threads == 0 { std::thread::available_parallelism().map_or(4, |n| n.get()) } else { cfg.relay.threads };
    let bind = cfg.relay.bind;
    // HTTPS, when asked for: certificates first, so a saved one serves from the first connection.
    let tls = if cfg.tls.enabled { Some(start_tls(&cfg)?) } else { None };
    let https_bind = cfg.tls.enabled.then_some(cfg.tls.https_bind);
    let http_bind = cfg.tls.http_bind.filter(|_| cfg.tls.enabled);

    let kinds = cfg.policy.kind_policy();
    let scfg = SessionCfg {
        max_subscriptions: cfg.limits.max_subscriptions,
        max_filters: cfg.limits.max_filters,
        max_filter_values: cfg.limits.max_filter_values,
        default_limit: cfg.limits.default_limit,
        max_limit: cfg.limits.max_limit,
        max_event_bytes: cfg.policy.max_event_bytes,
        max_future_seconds: cfg.policy.max_future_seconds,
        max_tags: cfg.policy.max_tags,
        kind_allowed: Box::new(move |k| kinds.allows(k)),
    };

    let (wtx, wrx) = mpsc::sync_channel(WRITE_QUEUE);
    let shared = Arc::new(Shared::new(cfg, scfg, store.clone(), wtx, threads));
    let mut txs = Vec::with_capacity(threads);
    let mut rxs = Vec::with_capacity(threads);
    for _ in 0..threads {
        let (tx, rx) = tmpsc::unbounded_channel();
        txs.push(tx);
        rxs.push(rx);
    }
    assert!(shared.reactors.set(txs.clone()).is_ok(), "reactors are set once");

    let make_sinks = |txs: &[tmpsc::UnboundedSender<crate::ingest::ReactorMsg>]| -> Vec<Sink> {
        txs.iter()
            .cloned()
            .map(|tx| {
                let s: Sink = Box::new(move |m| {
                    let _ = tx.send(m);
                });
                s
            })
            .collect()
    };
    let sinks = make_sinks(&txs);
    let reply_sinks = make_sinks(&txs);
    let writer = std::thread::Builder::new()
        .name("writer".into())
        .spawn(move || ingest::run(w, store, wrx, sinks, reply_sinks))
        .map_err(|e| e.to_string())?;

    // The socket is set up through tokio, which needs a runtime in scope.
    let (l, tl) = {
        let setup = tokio::runtime::Builder::new_current_thread().enable_io().build().map_err(|e| e.to_string())?;
        let _enter = setup.enter();
        let l = reactor::listener(bind).map_err(|e| listen_error(bind, &e))?;
        let tl = https_bind.map(|a| reactor::listener(a).map_err(|e| listen_error(a, &e))).transpose()?;
        (l, tl)
    };
    let mut conn_txs = Vec::with_capacity(threads);
    for (i, rx) in rxs.into_iter().enumerate() {
        let (ctx, crx) = tmpsc::unbounded_channel();
        conn_txs.push(ctx);
        let sh = shared.clone();
        std::thread::Builder::new().name(format!("reactor-{i}")).spawn(move || reactor::run(i, sh, crx, rx)).map_err(|e| e.to_string())?;
    }
    if let (Some(tl), Some(tls)) = (tl, &tls) {
        let (conns, config) = (conn_txs.clone(), tls.config.clone());
        std::thread::Builder::new().name("acceptor-tls".into()).spawn(move || reactor::accept_loop(tl, conns, Some(config))).map_err(|e| e.to_string())?;
    }
    std::thread::Builder::new().name("acceptor".into()).spawn(move || reactor::accept_loop(l, conn_txs, None)).map_err(|e| e.to_string())?;
    eprintln!(
        "{} {} listening on {bind}: {threads} reactors, {events} events, ready in {:.2}s",
        crate::brand::NAME,
        crate::brand::VERSION,
        t.elapsed().as_secs_f64()
    );
    if let Some(a) = https_bind {
        let plain = http_bind.map_or(String::new(), |h| format!(", plain http on {h} (certificate checks and a redirect to https)"));
        eprintln!("tls: https on {a}{plain}");
    }

    wait_for_signal();
    eprintln!("shutting down: finishing the batch in flight");
    ingest::SHUTDOWN.store(true, Ordering::Release);
    let _ = writer.join();
    eprintln!("stopped cleanly");
    std::process::exit(0);
}

/// Starts the HTTPS side: binds the plain-HTTP port, loads or begins obtaining a
/// certificate, and returns what the HTTPS acceptor needs.
fn start_tls(cfg: &Config) -> Result<relay_tls::Tls, String> {
    let t = &cfg.tls;
    let http = t.http_bind.map(|a| std::net::TcpListener::bind(a).map_err(|e| listen_error(a, &e))).transpose()?;
    let names = t.names(&cfg.relay.urls);
    let source = if t.uses_files() {
        relay_tls::Source::Files { cert: t.cert.clone().into(), key: t.key.clone().into() }
    } else {
        relay_tls::Source::Acme { domains: names.clone(), email: Some(t.email.clone()).filter(|e| !e.is_empty()), directory: t.directory_url().to_string() }
    };
    // Like RELAY_DEBUG_WRITER, a switch for tests: look at certificate files every N
    // milliseconds instead of every minute.
    let mut timing = relay_tls::Timing::default();
    if let Some(ms) = std::env::var("RELAY_DEBUG_TLS_POLL_MS").ok().and_then(|v| v.parse().ok()) {
        timing.files_poll = std::time::Duration::from_millis(ms);
    }
    relay_tls::Tls::start(relay_tls::Options {
        data_dir: cfg.store.data.clone(),
        source,
        http,
        https_port: t.https_bind.port(),
        redirect_hosts: names,
        user_agent: format!("{}/{}", crate::brand::SLUG, crate::brand::VERSION),
        ca_roots: Vec::new(),
        timing,
    })
}

/// "cannot listen on ADDR: why", with the usual fix for the usual reasons.
fn listen_error(addr: SocketAddr, e: &std::io::Error) -> String {
    let hint = match e.kind() {
        std::io::ErrorKind::PermissionDenied if addr.port() < 1024 => " (ports below 1024 need the program to run as root, or on Linux to hold the CAP_NET_BIND_SERVICE capability; or choose a higher port)",
        std::io::ErrorKind::AddrInUse => " (another program is using that port)",
        _ => "",
    };
    format!("cannot listen on {addr}: {e}{hint}")
}

fn wait_for_signal() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("signal runtime");
    rt.block_on(async {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    });
}
