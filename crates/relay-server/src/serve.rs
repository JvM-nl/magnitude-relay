//! `serve`: start the relay. Also what running the binary with no arguments does.

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
    let shared = Arc::new(Shared::new(cfg, scfg, store.clone(), wtx));
    let mut txs = Vec::with_capacity(threads);
    let mut rxs = Vec::with_capacity(threads);
    for _ in 0..threads {
        let (tx, rx) = tmpsc::unbounded_channel();
        txs.push(tx);
        rxs.push(rx);
    }
    assert!(shared.reactors.set(txs.clone()).is_ok(), "reactors are set once");

    let sinks: Vec<Sink> = txs
        .into_iter()
        .map(|tx| {
            let s: Sink = Box::new(move |m| {
                let _ = tx.send(m);
            });
            s
        })
        .collect();
    let writer = std::thread::Builder::new()
        .name("writer".into())
        .spawn(move || ingest::run(w, store, wrx, sinks))
        .map_err(|e| e.to_string())?;

    // Sockets are set up through tokio, which needs a runtime in scope; each
    // reactor then adopts its listener into its own runtime.
    let setup = tokio::runtime::Builder::new_current_thread().enable_io().build().map_err(|e| e.to_string())?;
    let _enter = setup.enter();
    for (i, rx) in rxs.into_iter().enumerate() {
        // Linux spreads connections over every reactor's own SO_REUSEPORT
        // listener; elsewhere reactor 0 accepts for everyone.
        let l = if cfg!(target_os = "linux") || i == 0 {
            Some(reactor::listener(bind).map_err(|e| format!("cannot listen on {bind}: {e}"))?)
        } else {
            None
        };
        let sh = shared.clone();
        std::thread::Builder::new().name(format!("reactor-{i}")).spawn(move || reactor::run(i, sh, l, rx)).map_err(|e| e.to_string())?;
    }
    drop(_enter);
    eprintln!(
        "{} {} listening on {bind}: {threads} reactors, {events} events, ready in {:.2}s",
        crate::brand::NAME,
        crate::brand::VERSION,
        t.elapsed().as_secs_f64()
    );

    wait_for_signal();
    eprintln!("shutting down: finishing the batch in flight");
    ingest::SHUTDOWN.store(true, Ordering::Release);
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
