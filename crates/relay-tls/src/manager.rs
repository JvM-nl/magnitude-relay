//! Keeps a certificate in service: loads what is saved, obtains or renews in the
//! background, and swaps the result in for the next handshake.
//!
//! One thread with its own small runtime does all of it, so the relay's reactors
//! never wait on a CA. Two sources: an ACME CA (the default; names in, certificate
//! out, renewed with a third of its lifetime left) or a pair of files that are
//! reloaded when they change.

use crate::acme::{self, Method};
use crate::certs::{self, Certs, Current};
use crate::port80::{self, Redirect};
use crate::{http, store, time};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Where the certificate comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// Obtained for `domains` from the CA at `directory`, with an optional contact.
    Acme { domains: Vec<String>, email: Option<String>, directory: String },
    /// Read from PEM files, and read again when they change.
    Files { cert: PathBuf, key: PathBuf },
}

/// The clocks of the background work. The defaults are the policy; tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// First wait after a failed attempt.
    pub retry_initial: Duration,
    /// Each further failure doubles the wait, up to this.
    pub retry_max: Duration,
    /// The certificate's age is looked at at least this often.
    pub check: Duration,
    /// How often a file certificate's files are looked at for changes.
    pub files_poll: Duration,
    pub acme: acme::Timing,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            retry_initial: Duration::from_secs(60),
            retry_max: Duration::from_secs(3600),
            check: Duration::from_secs(24 * 3600),
            files_poll: Duration::from_secs(60),
            acme: acme::Timing::default(),
        }
    }
}

pub struct Options {
    /// The relay's data directory; the account and certificate live in its `tls` folder.
    pub data_dir: PathBuf,
    pub source: Source,
    /// The already bound plain-HTTP socket (HTTP-01 challenges and the redirect), or
    /// none for no plain-HTTP port. Without it only TLS-ALPN-01 can prove control.
    pub http: Option<TcpListener>,
    /// The HTTPS port the redirect points at.
    pub https_port: u16,
    /// Names the redirect may send a visitor to; the first is the default.
    pub redirect_hosts: Vec<String>,
    /// Sent to the CA, which asks clients to say who they are.
    pub user_agent: String,
    /// Roots to trust for the CA's own HTTPS beyond the public ones (a private CA).
    pub ca_roots: Vec<Vec<u8>>,
    pub timing: Timing,
}

/// When a certificate should be renewed: with a third of its lifetime left.
pub fn renew_at(info: &crate::x509::CertInfo) -> i64 {
    info.not_before + (info.not_after - info.not_before) * 2 / 3
}

/// The wait after `previous` when an attempt fails again.
pub fn next_backoff(previous: Duration, t: &Timing) -> Duration {
    previous.saturating_mul(2).min(t.retry_max)
}

fn show_wait(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        _ if s >= 3600 && s % 3600 == 0 => format!("{}h", s / 3600),
        _ if s >= 60 && s % 60 == 0 => format!("{}m", s / 60),
        _ if s >= 60 => format!("{}m{}s", s / 60, s % 60),
        _ if s == 0 => format!("{}ms", d.as_millis()),
        _ => format!("{s}s"),
    }
}

#[derive(Default)]
struct Control {
    renew: Notify,
    force: AtomicBool,
    /// Set off when the owning [`Tls`] is dropped.
    stop: Notify,
}

impl Control {
    fn take_force(&self) -> bool {
        self.force.swap(false, Ordering::AcqRel)
    }

    /// Sleeps for `d`, or until a renewal is asked for.
    async fn sleep(&self, d: Duration) {
        tokio::select! {
            _ = tokio::time::sleep(d) => {}
            _ = self.renew.notified() => {}
        }
    }
}

/// A running TLS setup: what to accept connections with, and a handle on the
/// certificate behind it.
pub struct Tls {
    /// Give this to the acceptor of every TLS connection.
    pub config: Arc<ServerConfig>,
    certs: Arc<Certs>,
    control: Arc<Control>,
}

impl Tls {
    /// Loads what is saved (or, for files, what is configured; a problem there is an
    /// error here) and starts the background thread. With no usable certificate
    /// yet, handshakes fail until the first one is obtained.
    pub fn start(opts: Options) -> Result<Tls, String> {
        let dir = store::Dir::open(&opts.data_dir).map_err(|e| format!("{}: {e}", opts.data_dir.join("tls").display()))?;
        let certs = Arc::new(Certs::default());
        let control = Arc::new(Control::default());
        let config = certs::server_config(certs.clone())?;
        let ca_roots: Vec<CertificateDer<'static>> = opts.ca_roots.iter().cloned().map(CertificateDer::from).collect();
        // Fail on a bad CA root now rather than at the first renewal.
        http::Client::new(&opts.user_agent, &ca_roots)?;

        let mut stale = false;
        let seen = match &opts.source {
            Source::Files { cert, key } => {
                let c = read_pair(cert, key)?;
                eprintln!(
                    "tls: serving the certificate in {} for {} (expires {})",
                    cert.display(),
                    names(&c.info.names),
                    time::format(c.info.not_after)
                );
                certs.set(c);
                Some(stamp(cert, key))
            }
            Source::Acme { domains, directory, .. } => {
                match dir.load() {
                    Ok(Some(saved)) => match certs::load(&saved.chain_pem, &saved.key_pem) {
                        Ok(c) if c.info.not_after <= time::now() => {
                            eprintln!("tls: the saved certificate expired on {}", time::format(c.info.not_after))
                        }
                        Ok(c) => {
                            stale = !c.info.covers(domains) || saved.directory.as_deref() != Some(directory);
                            eprintln!(
                                "tls: serving the saved certificate for {} (expires {})",
                                names(&c.info.names),
                                time::format(c.info.not_after)
                            );
                            if stale {
                                eprintln!("tls: it does not match the current names or CA, so a new one will be requested");
                            }
                            certs.set(c);
                        }
                        Err(e) => eprintln!("tls: the saved certificate cannot be used ({e}); a new one will be requested"),
                    },
                    Ok(None) => {}
                    Err(e) => eprintln!("tls: cannot read the saved certificate: {e}"),
                }
                None
            }
        };

        let ctx = Ctx {
            certs: certs.clone(),
            control: control.clone(),
            dir,
            user_agent: opts.user_agent,
            ca_roots,
            timing: opts.timing,
            methods: if opts.http.is_some() { vec![Method::TlsAlpn01, Method::Http01] } else { vec![Method::TlsAlpn01] },
        };
        let redirect = Arc::new(Redirect { hosts: opts.redirect_hosts, https_port: opts.https_port });
        let (http, source) = (opts.http, opts.source);
        if let Some(l) = &http {
            l.set_nonblocking(true).map_err(|e| e.to_string())?;
        }
        std::thread::Builder::new()
            .name("tls".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tls runtime");
                rt.block_on(async move {
                    let stop = ctx.control.clone();
                    let work = async move {
                        if let Some(l) = http {
                            match tokio::net::TcpListener::from_std(l) {
                                Ok(l) => {
                                    tokio::spawn(port80::serve(l, ctx.certs.clone(), redirect));
                                }
                                Err(e) => eprintln!("tls: cannot use the plain-HTTP port: {e}"),
                            }
                        }
                        match source {
                            Source::Acme { domains, email, directory } => ctx.keep_fresh(domains, email, directory, stale).await,
                            Source::Files { cert, key } => ctx.watch_files(cert, key, seen.unwrap_or_default()).await,
                        }
                    };
                    // The relay never drops its `Tls`; tests do, and the thread, the plain-HTTP
                    // port and any request in flight go with it.
                    tokio::select! {
                        _ = work => {}
                        _ = stop.stop.notified() => {}
                    }
                });
            })
            .map_err(|e| e.to_string())?;
        Ok(Tls { config, certs, control })
    }

    /// The certificate being served, if there is one yet.
    pub fn certificate(&self) -> Option<Arc<Current>> {
        self.certs.current()
    }

    /// The challenge answers currently in place (empty between orders).
    pub fn challenges(&self) -> &certs::Challenges {
        &self.certs.challenges
    }

    /// Asks for a new certificate now instead of when one is due.
    pub fn renew_now(&self) {
        self.control.force.store(true, Ordering::Release);
        self.control.renew.notify_one();
    }
}

impl Drop for Tls {
    /// Ends the background thread. Connections already accepted keep the certificate
    /// they were handed.
    fn drop(&mut self) {
        self.control.stop.notify_one();
    }
}

fn names(n: &[String]) -> String {
    n.join(", ")
}

/// Reads a certificate and its key from files.
fn read_pair(cert: &Path, key: &Path) -> Result<Current, String> {
    let read = |p: &Path, what: &str| std::fs::read_to_string(p).map_err(|e| format!("cannot read the {what} {}: {e}", p.display()));
    let (c, k) = (read(cert, "certificate")?, read(key, "private key")?);
    certs::load(&c, &k).map_err(|e| format!("{} and {}: {e}", cert.display(), key.display()))
}

/// What identifies the state of a file: changing the contents, replacing the file
/// (a new inode) and touching it are all noticed.
type Stamp = [Option<(u128, u64, u64)>; 2];

fn stamp(cert: &Path, key: &Path) -> Stamp {
    let one = |p: &Path| {
        let m = std::fs::metadata(p).ok()?;
        let modified = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(&m);
        #[cfg(not(unix))]
        let inode = 0;
        Some((modified, m.len(), inode))
    };
    [one(cert), one(key)]
}

struct Ctx {
    certs: Arc<Certs>,
    control: Arc<Control>,
    dir: store::Dir,
    user_agent: String,
    ca_roots: Vec<CertificateDer<'static>>,
    timing: Timing,
    methods: Vec<Method>,
}

impl Ctx {
    /// Obtains a certificate when there is none or one is due, forever.
    async fn keep_fresh(&self, domains: Vec<String>, email: Option<String>, directory: String, mut stale: bool) {
        let mut backoff = self.timing.retry_initial;
        let mut told_terms = false;
        loop {
            let now = time::now();
            let due = match self.certs.current() {
                Some(c) if !stale => renew_at(&c.info),
                _ => now,
            };
            let forced = self.control.take_force();
            if due > now && !forced {
                self.control.sleep(Duration::from_secs((due - now) as u64).min(self.timing.check)).await;
                continue;
            }
            let result = match self.attempt(&domains, email.as_deref(), &directory, &mut told_terms).await {
                Ok(issued) => self.install(issued, &domains, &directory),
                Err(e) => Err(e),
            };
            match result {
                Ok(due_already) => {
                    stale = false;
                    backoff = self.timing.retry_initial;
                    if due_already {
                        // A certificate that is due the moment it arrives (a CA with a very
                        // short lifetime, or a wrong clock) must not turn this loop into a
                        // request every few milliseconds.
                        eprintln!(
                            "tls: the new certificate is already due for renewal; waiting {} before asking again",
                            show_wait(backoff)
                        );
                        self.control.sleep(backoff).await;
                    }
                }
                Err(e) => {
                    eprintln!("tls: could not get a certificate for {}: {e}; trying again in {}", names(&domains), show_wait(backoff));
                    self.control.sleep(backoff).await;
                    backoff = next_backoff(backoff, &self.timing);
                }
            }
        }
    }

    /// Saves a certificate the CA issued, then puts it in service, and says so. Saved
    /// first, so a certificate in use is one a restart finds. Whether it is already
    /// due for renewal is returned.
    fn install(&self, issued: acme::Issued, domains: &[String], directory: &str) -> Result<bool, String> {
        let renewed = self.certs.current().is_some();
        let cert = certs::load(&issued.chain_pem, &issued.key_pem).map_err(|e| format!("the CA's certificate cannot be used: {e}"))?;
        let until = time::format(cert.info.not_after);
        let saved = store::Saved { chain_pem: issued.chain_pem, key_pem: issued.key_pem, directory: Some(directory.to_string()) };
        if let Err(e) = self.dir.save(&saved) {
            eprintln!(
                "tls: could not save the certificate in {} (it is used anyway, and will be requested again after a restart): {e}",
                self.dir.path().display()
            );
        }
        let due_already = renew_at(&cert.info) <= time::now();
        self.certs.set(cert);
        eprintln!(
            "tls: {} a certificate for {} (valid until {until}, validated by {})",
            if renewed { "renewed" } else { "obtained" },
            names(domains),
            issued.method.name()
        );
        Ok(due_already)
    }

    /// One try at an order: TLS-ALPN-01 first, then HTTP-01 when the plain port is up.
    async fn attempt(
        &self,
        domains: &[String],
        email: Option<&str>,
        directory: &str,
        told_terms: &mut bool,
    ) -> Result<acme::Issued, String> {
        let key = self.dir.account_key()?;
        let http = http::Client::new(&self.user_agent, &self.ca_roots)?;
        let mut client = acme::Client::connect(http, directory, key, email, self.timing.acme).await.map_err(|e| e.to_string())?;
        if let (false, Some(terms)) = (*told_terms, client.terms()) {
            eprintln!("tls: requesting certificates from {directory} agrees to its terms of service: {terms}");
            *told_terms = true;
        }
        let mut failures = Vec::new();
        for &method in &self.methods {
            match client.obtain(domains, method, &self.certs.challenges).await {
                Ok(issued) => return Ok(issued),
                Err(e) => failures.push(format!("{}: {e}", method.name())),
            }
        }
        Err(failures.join("; then "))
    }

    /// Reloads a file certificate when its files change.
    async fn watch_files(&self, cert: PathBuf, key: PathBuf, mut seen: Stamp) {
        loop {
            tokio::time::sleep(self.timing.files_poll).await;
            let now = stamp(&cert, &key);
            if now == seen {
                continue;
            }
            seen = now;
            match read_pair(&cert, &key) {
                Ok(c) => {
                    eprintln!(
                        "tls: reloaded the certificate in {} for {} (expires {})",
                        cert.display(),
                        names(&c.info.names),
                        time::format(c.info.not_after)
                    );
                    self.certs.set(c);
                }
                Err(e) => eprintln!("tls: not reloading: {e}; still serving the previous certificate"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::CertInfo;

    fn info(nb: i64, na: i64) -> CertInfo {
        CertInfo {
            serial: vec![1],
            not_before: nb,
            not_after: na,
            names: vec![],
            subject_cn: None,
            issuer_cn: None,
            spki: vec![],
            acme_identifier: None,
        }
    }

    #[test]
    fn renewal_is_due_with_a_third_of_the_lifetime_left() {
        // 90 days: renew on day 60 (30 days left).
        let day = 86_400;
        assert_eq!(renew_at(&info(0, 90 * day)), 60 * day);
        // A 6-day certificate is renewed after 4 days.
        assert_eq!(renew_at(&info(1000, 1000 + 6 * day)), 1000 + 4 * day);
        // Always strictly inside the lifetime.
        for life in [3, 4, 90, 3600, 7_776_000] {
            let r = renew_at(&info(100, 100 + life));
            assert!(r > 100 && r < 100 + life, "{life}");
        }
    }

    #[test]
    fn failures_back_off_from_a_minute_to_an_hour() {
        let t = Timing::default();
        let mut waits = vec![t.retry_initial];
        while *waits.last().unwrap() < t.retry_max {
            waits.push(next_backoff(*waits.last().unwrap(), &t));
        }
        let minutes: Vec<u64> = waits.iter().map(|d| d.as_secs() / 60).collect();
        assert_eq!(minutes, [1, 2, 4, 8, 16, 32, 60]);
        assert_eq!(next_backoff(t.retry_max, &t), t.retry_max, "and stays there");
        assert_eq!(next_backoff(Duration::MAX, &t), t.retry_max, "without overflowing");
    }

    #[test]
    fn waits_read_naturally() {
        assert_eq!(show_wait(Duration::from_secs(60)), "1m");
        assert_eq!(show_wait(Duration::from_secs(120)), "2m");
        assert_eq!(show_wait(Duration::from_secs(3600)), "1h");
        assert_eq!(show_wait(Duration::from_secs(90)), "1m30s");
        assert_eq!(show_wait(Duration::from_secs(5)), "5s");
        assert_eq!(show_wait(Duration::from_millis(40)), "40ms");
    }

    #[test]
    fn defaults_are_the_policy() {
        let t = Timing::default();
        assert_eq!((t.retry_initial.as_secs(), t.retry_max.as_secs(), t.check.as_secs(), t.files_poll.as_secs()), (60, 3600, 86_400, 60));
    }
}
