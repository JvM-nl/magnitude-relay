//! The admin socket: how `query`, `count` and `delete` reach a running relay,
//! whose data directory they cannot open themselves.
//!
//! A Unix socket at `<data>/admin.sock`, mode 0600. Whoever may open it may run
//! operator commands, so file permissions are the whole authentication and
//! nothing listens on the network. A connection is one request, a single JSON
//! line, answered with JSON lines:
//!
//! ```text
//! {"op":"query","filters":[...],"limit":N}
//!     {"event":{...}} per event, newest first, then {"done":true,"count":N}
//! {"op":"count","filters":[...]}
//!     {"count":N}
//! {"op":"delete","filters":[...],"age":S,"all":true,"dry_run":true}
//!     {"matched":N,"deleted":0,"sample":[{"id":..,"kind":..,"created_at":..,"pubkey":..}]}
//! {"op":"delete",...} without "dry_run"
//!     {"progress":N} after each batch, then {"matched":N,"deleted":M,"sample":[]}
//! ```
//!
//! Any failure is `{"error":"..."}`. Reads run on a snapshot in the
//! connection's own thread, off the reactors and the writer. A delete finds its
//! events there too, but only the writer thread may kill them: the kills go to
//! it a batch at a time (see `ingest::Control`), between its own work.

use crate::ingest::{self, Control};
use crate::operator::{self, Deleted, Sample};
use relay_proto::filter::FilterError;
use relay_proto::json::{self, RawStr, Scanner};
use relay_proto::record::push_u64;
use relay_proto::{hex, Filter};
use relay_store::writer::DELETE_BATCH;
use relay_store::{Store, Version};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::time::Duration;

/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a client may stop reading before it is dropped: it holds a
/// snapshot, which keeps deleted bytes on disk.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// A request is one line. Filters can be long (hundreds of authors), but not this long.
const MAX_REQUEST: u64 = 16 << 20;
/// Connections served at once; more are turned away.
const MAX_CONNECTIONS: usize = 4;
const STOPPING: &str = "the relay is shutting down";

pub fn socket_path(data: &Path) -> PathBuf {
    data.join("admin.sock")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Query,
    Count,
    Delete,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub op: Op,
    pub filters: Vec<Filter>,
    /// query: at most this many events.
    pub limit: Option<u64>,
    /// delete: only events created more than this many seconds ago.
    pub age: Option<u64>,
    /// delete: the filters may match every event.
    pub all: bool,
    /// delete: change nothing, say what would go.
    pub dry_run: bool,
}

/// Why a request or reply could not be read.
struct Bad(String);

impl From<json::Error> for Bad {
    fn from(e: json::Error) -> Bad {
        Bad(e.to_string())
    }
}

impl From<FilterError> for Bad {
    fn from(e: FilterError) -> Bad {
        Bad(e.to_string())
    }
}

impl From<&str> for Bad {
    fn from(e: &str) -> Bad {
        Bad(e.to_string())
    }
}

fn boolean(s: &mut Scanner<'_>) -> Result<bool, Bad> {
    match s.raw_value()? {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err("expected true or false".into()),
    }
}

impl Request {
    pub fn new(op: Op, filters: Vec<Filter>) -> Request {
        Request { op, filters, limit: None, age: None, all: false, dry_run: false }
    }

    fn to_line(&self) -> String {
        let mut out = Vec::new();
        out.extend_from_slice(match self.op {
            Op::Query => b"{\"op\":\"query\",\"filters\":[",
            Op::Count => b"{\"op\":\"count\",\"filters\":[",
            Op::Delete => b"{\"op\":\"delete\",\"filters\":[",
        });
        for (i, f) in self.filters.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            f.write_json(&mut out);
        }
        out.push(b']');
        for (key, v) in [("limit", self.limit), ("age", self.age)] {
            if let Some(v) = v {
                out.extend_from_slice(format!(",\"{key}\":").as_bytes());
                push_u64(&mut out, v);
            }
        }
        for (key, v) in [("all", self.all), ("dry_run", self.dry_run)] {
            if v {
                out.extend_from_slice(format!(",\"{key}\":true").as_bytes());
            }
        }
        out.push(b'}');
        String::from_utf8(out).expect("request JSON is UTF-8")
    }

    fn parse(line: &str) -> Result<Request, String> {
        let mut s = Scanner::new(line);
        let mut op = None;
        let mut r = Request::new(Op::Query, Vec::new());
        s.object(|s, key| -> Result<(), Bad> {
            match key.bytes {
                b"op" => {
                    let v = s.string()?;
                    op = Some(match (v.escaped, v.bytes) {
                        (false, b"query") => Op::Query,
                        (false, b"count") => Op::Count,
                        (false, b"delete") => Op::Delete,
                        _ => return Err("unknown op".into()),
                    });
                }
                b"filters" => s.array(|s| -> Result<(), Bad> {
                    r.filters.push(Filter::parse(s)?);
                    Ok(())
                })?,
                b"limit" => r.limit = Some(s.u64()?),
                b"age" => r.age = Some(s.u64()?),
                b"all" => r.all = boolean(s)?,
                b"dry_run" => r.dry_run = boolean(s)?,
                _ => return Err("unknown key".into()),
            }
            Ok(())
        })
        .map_err(|b| b.0)?;
        s.end().map_err(|e| e.to_string())?;
        r.op = op.ok_or("no op")?;
        Ok(r)
    }
}

// The server.

/// The listening socket, for `serve` to take down on shutdown.
pub struct Admin {
    path: PathBuf,
}

impl Admin {
    /// Removes the socket file, so that no one finds it once the relay is gone.
    pub fn stop(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Starts listening on `<data>/admin.sock`. Events are killed through `ctl`.
pub fn start(data: &Path, store: Store, ctl: Sender<Control>) -> io::Result<Admin> {
    let path = socket_path(data);
    let listener = bind(&path)?;
    std::thread::Builder::new().name("admin".into()).spawn(move || accept_loop(listener, store, ctl))?;
    Ok(Admin { path })
}

/// A socket that only its owner can open, from the moment it exists. Its mode
/// can be set only after `bind` creates it, so it is bound inside a directory
/// no one else can enter, restricted, and then moved into place.
fn bind(path: &Path) -> io::Result<UnixListener> {
    // Whatever socket is already there was left by a crash: the store's lock,
    // which this process holds, proves no other relay uses the directory.
    // Anything else is not ours to replace.
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_socket() => return Err(io::Error::other(format!("{} exists and is not a socket", path.display()))),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let tmp = path.with_extension("tmp");
    let inner = tmp.join("s");
    check_len(path)?;
    check_len(&inner)?;
    let bound = bind_private(&tmp, &inner, path);
    if bound.is_err() {
        let _ = std::fs::remove_file(&inner);
    }
    let _ = std::fs::remove_dir(&tmp);
    bound
}

fn bind_private(tmp: &Path, inner: &Path, path: &Path) -> io::Result<UnixListener> {
    match std::fs::DirBuilder::new().mode(0o700).create(tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o700))?,
        Err(e) => return Err(e),
    }
    // A leftover of a crash between here and the rename.
    let _ = std::fs::remove_file(inner);
    let listener = UnixListener::bind(inner)?;
    std::fs::set_permissions(inner, std::fs::Permissions::from_mode(0o600))?;
    // Replaces a stale socket in one step.
    std::fs::rename(inner, path)?;
    Ok(listener)
}

/// A socket path must fit `sun_path`: 104 bytes with the NUL on macOS, 108 on Linux.
fn check_len(path: &Path) -> io::Result<()> {
    const MAX: usize = 103;
    if path.as_os_str().len() > MAX {
        return Err(io::Error::other(format!(
            "{} is too long for a Unix socket (at most {MAX} bytes); give the data directory a shorter path (a symlink will do)",
            path.display()
        )));
    }
    Ok(())
}

/// Counts a connection while it is served.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn accept_loop(listener: UnixListener, store: Store, ctl: Sender<Control>) {
    let open = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            // Out of descriptors, say: do not spin.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };
        if open.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::AcqRel);
            refuse(&mut &stream, "busy: too many admin connections, try again");
            continue;
        }
        let slot = Slot(open.clone());
        let (store, ctl) = (store.clone(), ctl.clone());
        // If no thread can be had the closure, and the slot with it, is dropped.
        let _ = std::thread::Builder::new().name("admin-conn".into()).spawn(move || {
            let _slot = slot;
            serve(&stream, &store, &ctl);
        });
    }
}

fn refuse(out: &mut impl Write, why: &str) {
    let mut line = b"{\"error\":\"".to_vec();
    json::escape_str(why, &mut line);
    line.extend_from_slice(b"\"}\n");
    let _ = out.write_all(&line);
}

fn serve(stream: &UnixStream, store: &Store, ctl: &Sender<Control>) {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut line = String::new();
    let read = BufReader::new(stream.take(MAX_REQUEST)).read_line(&mut line);
    let mut out = BufWriter::new(stream);
    let result = match read {
        Ok(0) => Err("no request".to_string()),
        Ok(n) if n as u64 >= MAX_REQUEST && !line.ends_with('\n') => Err("request too large".to_string()),
        Ok(_) => handle(&line, &mut out, store, ctl),
        Err(e) => Err(format!("cannot read the request: {e}")),
    };
    if let Err(why) = result {
        refuse(&mut out, &why);
    }
    let _ = out.flush();
}

fn handle(line: &str, out: &mut impl Write, store: &Store, ctl: &Sender<Control>) -> Result<(), String> {
    let req = Request::parse(line)?;
    operator::check_filters(&req.filters)?;
    let now = ingest::now();
    match req.op {
        Op::Query => {
            let v = store.snapshot();
            let mut buf = Vec::new();
            let n = operator::stream(&v, &req.filters, req.limit, now, &mut |rec| {
                buf.clear();
                buf.extend_from_slice(b"{\"event\":");
                rec.write_json(&mut buf);
                buf.extend_from_slice(b"}\n");
                out.write_all(&buf)
            })
            .map_err(|e| e.to_string())?;
            writeln!(out, "{{\"done\":true,\"count\":{n}}}").map_err(|e| e.to_string())
        }
        Op::Count => {
            let n = operator::count_matching(&store.snapshot(), &req.filters, now);
            writeln!(out, "{{\"count\":{n}}}").map_err(|e| e.to_string())
        }
        Op::Delete => delete(&req, out, store, ctl, now),
    }
}

fn delete(req: &Request, out: &mut impl Write, store: &Store, ctl: &Sender<Control>, now: u64) -> Result<(), String> {
    operator::check_delete(&req.filters, req.all)?;
    let older = operator::older_than(req.age, now);
    // Held until the kills are checkpointed: while a reader holds it, nothing
    // that was killed is zeroed on disk, and zeroing must not run ahead of the
    // checkpoint that makes the kills permanent.
    let v = store.snapshot();
    if req.dry_run {
        return write_deleted(out, &operator::preview(&v, &req.filters, older, now)).map_err(|e| e.to_string());
    }
    let (d, mut failed) = kill_matching(&v, &req.filters, older, now, ctl, &mut |deleted| {
        // The client going away (Ctrl-C) ends the delete after the batch in flight.
        writeln!(out, "{{\"progress\":{deleted}}}").and_then(|()| out.flush()).is_ok()
    });
    if d.deleted > 0 {
        if let Err(e) = checkpoint(ctl) {
            failed.get_or_insert(e);
        }
    }
    drop(v);
    match failed {
        Some(why) => Err(format!("{why} (deleted {} before stopping)", d.deleted)),
        None => write_deleted(out, &d).map_err(|e| e.to_string()),
    }
}

/// Hands what `filters` match to the writer to kill, a batch at a time. Returns
/// what was done, and why it stopped early if it did. `listening` is told the
/// running total after each batch and says whether to go on.
fn kill_matching(
    v: &Version,
    filters: &[Filter],
    older: Option<u64>,
    now: u64,
    ctl: &Sender<Control>,
    listening: &mut dyn FnMut(u64) -> bool,
) -> (Deleted, Option<String>) {
    let mut d = Deleted::default();
    let mut batch = Vec::with_capacity(DELETE_BATCH);
    for hit in v.matching(filters, older, now) {
        d.matched += 1;
        batch.push(hit.seq);
        if batch.len() < DELETE_BATCH {
            continue;
        }
        match kill(ctl, std::mem::take(&mut batch)) {
            Ok(n) => d.deleted += n,
            Err(e) => return (d, Some(e)),
        }
        if !listening(d.deleted) {
            return (d, None);
        }
    }
    match kill(ctl, batch) {
        Ok(n) => d.deleted += n,
        Err(e) => return (d, Some(e)),
    }
    (d, None)
}

/// Asks the writer to kill `seqs`; how many were still live.
fn kill(ctl: &Sender<Control>, seqs: Vec<u64>) -> Result<u64, String> {
    if seqs.is_empty() {
        return Ok(0);
    }
    let (reply, answer) = mpsc::channel();
    ctl.send(Control::Kill { seqs, reply }).map_err(|_| STOPPING.to_string())?;
    let n = answer.recv().map_err(|_| STOPPING.to_string())?.map_err(|e| e.to_string())?;
    Ok(n as u64)
}

fn checkpoint(ctl: &Sender<Control>) -> Result<(), String> {
    let (reply, answer) = mpsc::channel();
    ctl.send(Control::Checkpoint { reply }).map_err(|_| STOPPING.to_string())?;
    answer.recv().map_err(|_| STOPPING.to_string())?.map_err(|e| e.to_string())
}

fn write_deleted(out: &mut impl Write, d: &Deleted) -> io::Result<()> {
    let mut b = b"{\"matched\":".to_vec();
    push_u64(&mut b, d.matched);
    b.extend_from_slice(b",\"deleted\":");
    push_u64(&mut b, d.deleted);
    b.extend_from_slice(b",\"sample\":[");
    for (i, s) in d.sample.iter().enumerate() {
        if i > 0 {
            b.push(b',');
        }
        b.extend_from_slice(b"{\"id\":\"");
        hex::encode_into(&s.id, &mut b);
        b.extend_from_slice(b"\",\"kind\":");
        push_u64(&mut b, s.kind);
        b.extend_from_slice(b",\"created_at\":");
        push_u64(&mut b, s.created_at);
        b.extend_from_slice(b",\"pubkey\":\"");
        hex::encode_into(&s.pubkey, &mut b);
        b.extend_from_slice(b"\"}");
    }
    b.extend_from_slice(b"]}\n");
    out.write_all(&b)
}

// The client.

/// One connection to a running relay's admin socket, good for one request.
pub struct Client(UnixStream);

enum Reply<'a> {
    Event(&'a str),
    Progress,
    Done(u64),
    Count(u64),
    Deleted(Deleted),
}

impl Client {
    pub fn connect(sock: &Path) -> io::Result<Client> {
        check_len(sock)?;
        UnixStream::connect(sock).map(Client)
    }

    fn ask(mut self, req: &Request) -> io::Result<BufReader<UnixStream>> {
        let mut line = req.to_line();
        line.push('\n');
        self.0.write_all(line.as_bytes())?;
        Ok(BufReader::new(self.0))
    }

    /// Hands each event's JSON to `emit`, newest first. Returns how many.
    pub fn query(self, req: &Request, emit: &mut dyn FnMut(&str) -> io::Result<()>) -> io::Result<u64> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        let mut got = 0;
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Event(e) => {
                    emit(e)?;
                    got += 1;
                }
                Reply::Done(n) if n == got => return Ok(got),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }

    pub fn count(self, req: &Request) -> io::Result<u64> {
        let mut r = self.ask(req)?;
        match next_reply(&mut r, &mut String::new())? {
            Reply::Count(n) => Ok(n),
            _ => Err(io::Error::other("the relay's reply was not what was asked for")),
        }
    }

    pub fn delete(self, req: &Request) -> io::Result<Deleted> {
        let mut r = self.ask(req)?;
        let mut line = String::new();
        loop {
            match next_reply(&mut r, &mut line)? {
                Reply::Progress => {}
                Reply::Deleted(d) => return Ok(d),
                _ => return Err(io::Error::other("the relay's reply was not what was asked for")),
            }
        }
    }
}

/// The next reply line. The relay's own `{"error":..}` becomes the error.
fn next_reply<'a>(r: &mut impl BufRead, line: &'a mut String) -> io::Result<Reply<'a>> {
    line.clear();
    if r.read_line(line)? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the relay closed the connection before it finished"));
    }
    parse_reply(line).map_err(io::Error::other)?.map_err(io::Error::other)
}

/// `Ok(Err(message))` is a reply that says the request failed.
fn parse_reply(line: &str) -> Result<Result<Reply<'_>, String>, String> {
    if let Some(ev) = line.strip_prefix("{\"event\":").and_then(|l| l.trim_end().strip_suffix('}')) {
        return Ok(Ok(Reply::Event(ev)));
    }
    let (mut error, mut done, mut progress) = (None, false, false);
    let (mut count, mut matched, mut deleted) = (None, None, None);
    let mut sample = Vec::new();
    let mut s = Scanner::new(line);
    s.object(|s, key| -> Result<(), Bad> {
        match key.bytes {
            b"error" => error = Some(unescape(s.string()?)),
            b"done" => {
                s.skip()?;
                done = true;
            }
            b"progress" => {
                s.u64()?;
                progress = true;
            }
            b"count" => count = Some(s.u64()?),
            b"matched" => matched = Some(s.u64()?),
            b"deleted" => deleted = Some(s.u64()?),
            b"sample" => s.array(|s| -> Result<(), Bad> {
                sample.push(parse_sample(s)?);
                Ok(())
            })?,
            // A newer relay may say more.
            _ => s.skip()?,
        }
        Ok(())
    })
    .map_err(|b| format!("unreadable reply from the relay: {}", b.0))?;
    Ok(if let Some(msg) = error {
        Err(msg)
    } else if done {
        Ok(Reply::Done(count.unwrap_or(0)))
    } else if progress {
        Ok(Reply::Progress)
    } else if let (Some(matched), Some(deleted)) = (matched, deleted) {
        Ok(Reply::Deleted(Deleted { matched, deleted, sample }))
    } else if let Some(n) = count {
        Ok(Reply::Count(n))
    } else {
        Err("unreadable reply from the relay".to_string())
    })
}

fn parse_sample(s: &mut Scanner<'_>) -> Result<Sample, Bad> {
    let (mut id, mut pubkey, mut kind, mut created_at) = ([0u8; 32], [0u8; 32], 0, 0);
    let hex32 = |v: RawStr<'_>| hex::decode_32(v.bytes).ok_or(Bad("bad hex in a reply".into()));
    s.object(|s, key| -> Result<(), Bad> {
        match key.bytes {
            b"id" => id = hex32(s.string()?)?,
            b"pubkey" => pubkey = hex32(s.string()?)?,
            b"kind" => kind = s.u64()?,
            b"created_at" => created_at = s.u64()?,
            _ => s.skip()?,
        }
        Ok(())
    })?;
    Ok(Sample { id, kind, created_at, pubkey })
}

/// A JSON string's text. Only what `json::escape_str` writes needs undoing.
fn unescape(v: RawStr<'_>) -> String {
    let s = String::from_utf8_lossy(v.bytes);
    if !v.escaped {
        return s.into_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\x08'),
            Some('f') => out.push('\x0c'),
            Some('u') => {
                let code: String = chars.by_ref().take(4).collect();
                out.push(u32::from_str_radix(&code, 16).ok().and_then(char::from_u32).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filters(json: &str) -> Vec<Filter> {
        operator::parse_filters(json).unwrap()
    }

    #[test]
    fn requests_round_trip() {
        let h = "ab".repeat(32);
        let fs = filters(&format!(
            r##"[{{"kinds":[1059,14],"authors":["{h}"],"#p":["{h}"],"#t":["plain \"quoted\" tag"],"since":5,"until":9}},{{"ids":["{h}"]}},{{}}]"##
        ));
        for req in [
            Request::new(Op::Query, fs.clone()),
            Request { limit: Some(7), ..Request::new(Op::Query, fs.clone()) },
            Request::new(Op::Count, fs.clone()),
            Request { age: Some(86_400), all: true, dry_run: true, ..Request::new(Op::Delete, fs.clone()) },
            Request { age: Some(0), ..Request::new(Op::Delete, fs) },
        ] {
            let line = req.to_line();
            assert!(!line.contains('\n'), "one line: {line}");
            assert_eq!(Request::parse(&line).unwrap(), req, "{line}");
        }
    }

    #[test]
    fn bad_requests_say_why() {
        for (line, why) in [
            (r#"{"filters":[]}"#, "no op"),
            (r#"{"op":"drop","filters":[]}"#, "unknown op"),
            (r#"{"op":"count","filters":[],"oops":1}"#, "unknown key"),
            (r#"{"op":"count","filters":[{"nope":1}]}"#, "unknown key"),
            (r#"{"op":"delete","filters":[],"all":1}"#, "true or false"),
            (r#"{"op":"count""#, "byte"),
            ("", "byte"),
        ] {
            let err = Request::parse(line).unwrap_err();
            assert!(err.contains(why), "{line}: {err}");
        }
    }

    #[test]
    fn replies_are_told_apart() {
        let ev = r#"{"event":{"content":"a","id":"x"}}"#;
        assert!(matches!(parse_reply(ev), Ok(Ok(Reply::Event(e))) if e == r#"{"content":"a","id":"x"}"#));
        assert!(matches!(parse_reply(r#"{"done":true,"count":3}"#), Ok(Ok(Reply::Done(3)))));
        assert!(matches!(parse_reply(r#"{"count":9}"#), Ok(Ok(Reply::Count(9)))));
        assert!(matches!(parse_reply(r#"{"progress":4096}"#), Ok(Ok(Reply::Progress))));
        let id = "cd".repeat(32);
        let line = format!(r#"{{"matched":5,"deleted":0,"sample":[{{"id":"{id}","kind":14,"created_at":77,"pubkey":"{id}"}}]}}"#);
        let Ok(Ok(Reply::Deleted(d))) = parse_reply(&line) else { panic!("not a delete reply") };
        assert_eq!((d.matched, d.deleted, d.sample.len()), (5, 0, 1));
        assert_eq!((d.sample[0].kind, d.sample[0].created_at, d.sample[0].id), (14, 77, [0xcd; 32]));
        // And what a relay says when it fails survives its escaping.
        let mut e = b"{\"error\":\"".to_vec();
        json::escape_str("a \"b\" \\ c\nd", &mut e);
        e.extend_from_slice(b"\"}");
        let Ok(Err(msg)) = parse_reply(std::str::from_utf8(&e).unwrap()) else { panic!("not an error") };
        assert_eq!(msg, "a \"b\" \\ c\nd");
    }

    /// A store of `n` events and a stand-in for the writer thread that answers `Control`.
    fn store_with_a_writer(n: usize) -> (Store, Sender<Control>, std::thread::JoinHandle<()>) {
        use relay_proto::{event::parse_event_json, EventParser};
        let dir = std::env::temp_dir().join(format!("relay-admin-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, mut w) = Store::open(&dir, relay_store::Options { segment_size: 16 << 20, ..Default::default() }).unwrap();
        let mut parser = EventParser::new();
        let recs: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let json = format!(
                    r#"{{"id":"{:064x}","pubkey":"{:064x}","created_at":{},"kind":14,"tags":[],"content":"x","sig":"{}"}}"#,
                    i + 1,
                    1,
                    1_000 + i,
                    "00".repeat(64)
                );
                let mut rec = Vec::new();
                parse_event_json(&json, &mut parser, &mut rec, false).unwrap();
                rec
            })
            .collect();
        for chunk in recs.chunks(1_000) {
            let refs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
            w.write(&refs).unwrap();
        }
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            for c in rx {
                match c {
                    Control::Kill { seqs, reply } => reply.send(w.kill_live(&seqs)).unwrap(),
                    Control::Checkpoint { reply } => reply.send(w.write_checkpoint()).unwrap(),
                }
            }
        });
        (store, tx, thread)
    }

    #[test]
    fn a_departed_client_stops_a_delete_after_its_batch() {
        let n = DELETE_BATCH * 3 + 5;
        let (store, ctl, writer) = store_with_a_writer(n);
        let all = filters("{}");
        let v = store.snapshot();
        let mut told = Vec::new();
        let (d, failed) = kill_matching(&v, &all, None, ingest::now(), &ctl, &mut |deleted| {
            told.push(deleted);
            told.len() < 2
        });
        assert!(failed.is_none());
        // Two batches went; the client was told after each, and the second time it was gone.
        assert_eq!(told, [DELETE_BATCH as u64, DELETE_BATCH as u64 * 2]);
        assert_eq!(d.deleted, DELETE_BATCH as u64 * 2);
        assert_eq!(operator::count_matching(&store.snapshot(), &all, ingest::now()), (n - DELETE_BATCH * 2) as u64);

        // Left to finish, the rest goes (the events already killed are skipped), and the walk's total is what was killed.
        let (d, failed) = kill_matching(&store.snapshot(), &all, None, ingest::now(), &ctl, &mut |_| true);
        assert!(failed.is_none());
        assert_eq!((d.matched, d.deleted), ((n - DELETE_BATCH * 2) as u64, (n - DELETE_BATCH * 2) as u64));
        assert_eq!(operator::count_matching(&store.snapshot(), &all, ingest::now()), 0);

        drop((v, ctl));
        writer.join().unwrap();
    }

    #[test]
    fn a_writer_that_is_gone_is_an_error_not_a_hang() {
        let (gone, rx) = mpsc::channel::<Control>();
        drop(rx);
        assert_eq!(kill(&gone, vec![1, 2, 3]).unwrap_err(), STOPPING);
        assert_eq!(checkpoint(&gone).unwrap_err(), STOPPING);
        // One that stops between taking a request and answering it.
        let (ctl, rx) = mpsc::channel::<Control>();
        let stopper = std::thread::spawn(move || drop(rx.recv()));
        assert_eq!(kill(&ctl, vec![1]).unwrap_err(), STOPPING);
        stopper.join().unwrap();
    }
}
