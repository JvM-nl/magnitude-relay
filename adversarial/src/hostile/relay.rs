//! The relay under test: the real binary, started with a settings file of our
//! own on a free loopback port, watched (alive, RSS, open descriptors) while
//! it is attacked.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Relay {
    pub child: Child,
    pub addr: SocketAddr,
    pub dir: PathBuf,
    pub log: PathBuf,
}

/// The relay binary next to the workspace's release build, by the name the
/// relay's own brand file gives it.
pub fn default_binary() -> PathBuf {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    here.join("..").join("target").join("release").join(crate::brand::SLUG)
}

pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).expect("a free port")
}

impl Relay {
    /// Starts `bin` with `extra` appended to a settings file that binds a free
    /// loopback port, trusts `X-Real-IP` (so one machine can play many
    /// clients) and accepts every kind.
    pub fn start(bin: &Path, dir: &Path, threads: usize, extra: &str) -> std::io::Result<Relay> {
        Self::start_at(bin, dir, free_port(), threads, extra)
    }

    pub fn start_at(bin: &Path, dir: &Path, port: u16, threads: usize, extra: &str) -> std::io::Result<Relay> {
        std::fs::create_dir_all(dir)?;
        let cfg = dir.join("relay.toml");
        // Sections in `extra` are merged by appending keys under repeated headers,
        // which the relay's TOML refuses; so `extra` carries whole sections and
        // the base only what `extra` does not mention.
        let mut base = String::new();
        if !extra.contains("[relay]") {
            base.push_str(&format!("[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = {threads}\nreal_ip_header = \"x-real-ip\"\n"));
        }
        if !extra.contains("[policy]") {
            base.push_str("[policy]\nkinds = \"all\"\n");
        }
        if !extra.contains("[store]") {
            base.push_str(&format!("[store]\ndata = \"{}\"\n", dir.join("data").display()));
        }
        std::fs::write(&cfg, format!("{base}{extra}"))?;
        let log = dir.join("relay.log");
        let out = std::fs::File::create(&log)?;
        let child = Command::new(bin).arg("--config").arg(&cfg).stdout(Stdio::null()).stderr(out).spawn()?;
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut r = Relay { child, addr, dir: dir.to_path_buf(), log };
        let t = Instant::now();
        while std::net::TcpStream::connect(addr).is_err() {
            if let Some(status) = r.child.try_wait()? {
                return Err(std::io::Error::other(format!("relay exited at start ({status}): {}", r.log_tail(20))));
            }
            if t.elapsed() > Duration::from_secs(20) {
                return Err(std::io::Error::other("relay did not start listening"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(r)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// None while running; the exit status once it has died.
    pub fn exited(&mut self) -> Option<String> {
        self.child.try_wait().ok().flatten().map(|s| s.to_string())
    }

    pub fn log_tail(&self, n: usize) -> String {
        let t = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = t.lines().collect();
        lines[lines.len().saturating_sub(n)..].join(" | ")
    }

    /// Private memory in KiB: what the relay itself holds (heap, buffers),
    /// not the pages of its files the kernel happens to keep mapped in.
    pub fn rss_kb(&self) -> Option<u64> {
        rss_kb(self.pid())
    }

    /// Open file descriptors (sockets included).
    pub fn fds(&self) -> Option<u64> {
        fds(self.pid())
    }

    /// SIGTERM, then wait for a clean exit.
    pub fn stop(mut self) -> Result<(), String> {
        // SAFETY: signalling our own child.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let t = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(s)) if s.success() => return Ok(()),
                Ok(Some(s)) => return Err(format!("relay exited with {s} on SIGTERM: {}", self.log_tail(10))),
                Ok(None) if t.elapsed() > Duration::from_secs(30) => {
                    let _ = self.child.kill();
                    return Err("relay did not stop within 30 s of SIGTERM".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(e.to_string()),
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Anonymous resident memory (RssAnon): the relay's own, without the mapped
/// pages of its log and index files.
#[cfg(target_os = "linux")]
pub fn rss_kb(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("RssAnon:"))?.split_whitespace().next()?.parse().ok()
}

/// The physical footprint (what Activity Monitor calls Memory): dirty and
/// anonymous pages, not clean pages of mapped files.
#[cfg(target_os = "macos")]
pub fn rss_kb(pid: u32) -> Option<u64> {
    // SAFETY: a zeroed out-parameter of the flavour's own struct type.
    unsafe {
        let mut info: libc::rusage_info_v2 = std::mem::zeroed();
        let r = libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V2, (&mut info as *mut libc::rusage_info_v2).cast());
        (r == 0).then_some(info.ri_phys_footprint / 1024)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn rss_kb(pid: u32) -> Option<u64> {
    let out = Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output().ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(target_os = "linux")]
pub fn fds(pid: u32) -> Option<u64> {
    Some(std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?.count() as u64)
}

#[cfg(not(target_os = "linux"))]
pub fn fds(pid: u32) -> Option<u64> {
    let out = Command::new("lsof").args(["-n", "-P", "-p", &pid.to_string()]).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).lines().count().saturating_sub(1) as u64)
}

/// Raises this process's open-file limit (hostile scenarios hold thousands of sockets).
pub fn raise_nofile(want: u64) -> u64 {
    // SAFETY: plain getrlimit/setrlimit on our own process.
    unsafe {
        let mut r: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) != 0 {
            return 0;
        }
        let target = want.min(r.rlim_max as u64);
        if (r.rlim_cur as u64) < target {
            r.rlim_cur = target as libc::rlim_t;
            libc::setrlimit(libc::RLIMIT_NOFILE, &r);
        }
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut r);
        r.rlim_cur as u64
    }
}
