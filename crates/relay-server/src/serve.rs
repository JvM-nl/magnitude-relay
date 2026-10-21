//! `serve`: start the relay. Also what running the binary with no arguments does.

use crate::admin;
use crate::config::{store_options, Config};
use crate::ingest::{self, Sink};
use crate::reactor::{self, Shared};
use crate::session::SessionCfg;
use relay_store::Store;
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
    let data = cfg.store.data.clone();

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
    let (ctl_tx, ctl_rx) = mpsc::channel();
    let admin_store = store.clone();
    let writer = std::thread::Builder::new()
        .name("writer".into())
        .spawn(move || ingest::run(w, store, wrx, ctl_rx, sinks, reply_sinks))
        .map_err(|e| e.to_string())?;

    // Ready before the relay's own port is, so that a script which waits for
    // the port can run operator commands at once. Not fatal: the relay serves
    // without it.
    let admin = match admin::start(&data, admin_store, ctl_tx) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("admin socket unavailable ({e}): query, count and delete cannot reach this relay while it runs");
            None
        }
    };

    // The socket is set up through tokio, which needs a runtime in scope.
    let l = {
        let setup = tokio::runtime::Builder::new_current_thread().enable_io().build().map_err(|e| e.to_string())?;
        let _enter = setup.enter();
        match reactor::listener(bind) {
            Ok(l) => l,
            Err(e) => {
                if let Some(a) = &admin {
                    a.stop();
                }
                return Err(format!("cannot listen on {bind}: {e}"));
            }
        }
    };
    let mut conn_txs = Vec::with_capacity(threads);
    for (i, rx) in rxs.into_iter().enumerate() {
        let (ctx, crx) = tmpsc::unbounded_channel();
        conn_txs.push(ctx);
        let sh = shared.clone();
        std::thread::Builder::new().name(format!("reactor-{i}")).spawn(move || reactor::run(i, sh, crx, rx)).map_err(|e| e.to_string())?;
    }
    std::thread::Builder::new().name("acceptor".into()).spawn(move || reactor::accept_loop(l, conn_txs)).map_err(|e| e.to_string())?;
    eprintln!(
        "{} {} listening on {bind}: {threads} reactors, {events} events, ready in {:.2}s",
        crate::brand::NAME,
        crate::brand::VERSION,
        t.elapsed().as_secs_f64()
    );

    wait_for_signal();
    eprintln!("shutting down: finishing the batch in flight");
    ingest::SHUTDOWN.store(true, Ordering::Release);
    if let Some(a) = &admin {
        a.stop();
    }
    let _ = writer.join();
    eprintln!("stopped cleanly");
    std::process::exit(0);
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
