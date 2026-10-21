//! A TLS server connection driven the way the relay's reactors drive a plain
//! socket: wait for readiness, then read what is there without waiting, into a
//! buffer the reactor owns.
//!
//! tokio-rustls hides the socket behind `AsyncRead`, which would need a buffer held
//! across the wait; the reactors share one per core instead (an idle connection
//! owns no read buffer). So this wraps rustls's `ServerConnection` directly over a
//! tokio `TcpStream` using `try_read` / `try_write`, all the cryptography and the
//! protocol still being rustls's. It also implements `AsyncRead` and `AsyncWrite`
//! for the one-off parts of a connection (the HTTP upgrade, plain responses).

use crate::ACME_ALPN;
use rustls::{ServerConfig, ServerConnection};
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// A connection that finished its handshake only to answer a TLS-ALPN-01 probe
/// carries this message in the error [`TlsConn::accept`] returns for it.
pub const ACME_PROBE: &str = "acme-tls/1 validation connection";

/// The socket as `std::io` for rustls: every call returns at once, `WouldBlock`
/// when the socket is not ready (which also clears tokio's readiness flag, so the
/// next wait really waits).
struct Nb<'a>(&'a TcpStream);

impl Read for Nb<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.try_read(buf)
    }
}

impl Write for Nb<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.try_write(buf)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.0.try_write_vectored(bufs)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Pulled {
    /// Ciphertext arrived and was processed.
    Data,
    /// The peer sent nothing more, ever.
    Eof,
    /// Nothing to read right now.
    Blocked,
}

pub struct TlsConn {
    io: TcpStream,
    tls: ServerConnection,
    /// Decrypted bytes may be waiting inside `tls`, so the socket's readiness says
    /// nothing about whether a read would find data.
    buffered: bool,
    shutdown_started: bool,
}

impl TlsConn {
    /// Runs the server handshake. A connection that negotiated the TLS-ALPN-01
    /// protocol is a CA looking at the challenge certificate: it is closed and
    /// reported as an error ([`ACME_PROBE`]) so the caller does not speak HTTP to it.
    pub async fn accept(io: TcpStream, config: Arc<ServerConfig>) -> io::Result<TlsConn> {
        let tls = ServerConnection::new(config).map_err(io::Error::other)?;
        let mut c = TlsConn { io, tls, buffered: false, shutdown_started: false };
        while c.tls.is_handshaking() {
            c.flush().await?;
            if !c.tls.is_handshaking() {
                break;
            }
            c.io.readable().await?;
            match c.pull()? {
                Pulled::Eof => return Err(io::ErrorKind::UnexpectedEof.into()),
                Pulled::Data | Pulled::Blocked => {}
            }
        }
        // The last flight (the server's Finished, session tickets), and any alert.
        c.flush().await?;
        if c.tls.alpn_protocol() == Some(ACME_ALPN) {
            c.tls.send_close_notify();
            let _ = c.flush().await;
            return Err(io::Error::other(ACME_PROBE));
        }
        // The client's first request may have arrived with the handshake.
        c.buffered = true;
        Ok(c)
    }

    /// The application protocol negotiated, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }

    /// Reads ciphertext the socket has, once, and decrypts it.
    fn pull(&mut self) -> io::Result<Pulled> {
        match self.tls.read_tls(&mut Nb(&self.io)) {
            Ok(0) => return Ok(Pulled::Eof),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(Pulled::Blocked),
            Err(e) => return Err(e),
        }
        match self.tls.process_new_packets() {
            Ok(_) => {
                // Whatever rustls queued in answer (a key update, an alert) goes out
                // if the socket takes it; otherwise with the next write.
                if self.tls.wants_write() {
                    let _ = self.try_flush();
                }
                self.buffered = true;
                Ok(Pulled::Data)
            }
            Err(e) => {
                // Tell the peer why, if the socket will take it, then give up.
                let _ = self.try_flush();
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }

    /// Resolves when a [`try_read`](Self::try_read) is worth making: decrypted bytes
    /// are waiting, or the socket has something. Cancel-safe.
    pub async fn readable(&self) -> io::Result<()> {
        if self.buffered {
            return Ok(());
        }
        self.io.readable().await
    }

    /// Reads decrypted bytes without waiting. `Ok(0)` is the end of the stream (a
    /// clean close, or the peer vanishing without one, which many clients do);
    /// `WouldBlock` means nothing yet. `buf` must not be empty.
    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        debug_assert!(!buf.is_empty());
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => {
                    // A full buffer may leave more behind it.
                    self.buffered = n == buf.len();
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.buffered = false,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
            if let Pulled::Blocked = self.pull()? {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
    }

    /// Writes ciphertext rustls has queued, as far as the socket takes it now.
    fn try_flush(&mut self) -> io::Result<()> {
        while self.tls.wants_write() {
            match self.tls.write_tls(&mut Nb(&self.io)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Writes everything rustls has queued, waiting for the socket as needed.
    async fn flush(&mut self) -> io::Result<()> {
        while self.tls.wants_write() {
            match self.tls.write_tls(&mut Nb(&self.io)) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.io.writable().await?,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Encrypts and sends all of `buf`; returns when it is on the wire.
    pub async fn send(&mut self, mut buf: &[u8]) -> io::Result<()> {
        let mut stalled = false;
        while !buf.is_empty() {
            // rustls takes plaintext up to its buffer limit; draining after each
            // piece keeps the ciphertext it holds bounded.
            let n = self.tls.writer().write(buf)?;
            buf = &buf[n..];
            self.flush().await?;
            match (n, stalled) {
                (0, true) => return Err(io::ErrorKind::WriteZero.into()),
                (0, false) => stalled = true,
                _ => stalled = false,
            }
        }
        // Even with nothing to send, alerts or key updates may be queued.
        self.flush().await
    }

    fn poll_flush_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tls.wants_write() {
            ready!(self.io.poll_write_ready(cx))?;
            match self.tls.write_tls(&mut Nb(&self.io)) {
                Ok(_) => {}
                // Not actually ready: the attempt cleared the flag, so asking again waits.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for TlsConn {
    /// Closing says goodbye if the socket will take it: a peer that sees the
    /// stream end without a close_notify cannot tell a close from a truncation.
    fn drop(&mut self) {
        if !self.shutdown_started {
            self.tls.send_close_notify();
            let _ = self.try_flush();
        }
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let unfilled = buf.initialize_unfilled();
            let want = unfilled.len();
            if want == 0 {
                return Poll::Ready(Ok(()));
            }
            match this.tls.reader().read(unfilled) {
                Ok(n) => {
                    buf.advance(n);
                    this.buffered = n == want;
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => this.buffered = false,
                // The end of the stream, however it came.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(e)),
            }
            ready!(this.io.poll_read_ready(cx))?;
            this.pull()?;
        }
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut stalled = false;
        loop {
            match this.tls.writer().write(buf) {
                Ok(0) => {
                    // rustls's buffer is full: let the socket drain it first.
                    if stalled {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    stalled = true;
                    ready!(this.poll_flush_tls(cx))?;
                }
                Ok(n) => {
                    let _ = this.try_flush();
                    return Poll::Ready(Ok(n));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_tls(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shutdown_started {
            this.tls.send_close_notify();
            this.shutdown_started = true;
        }
        ready!(this.poll_flush_tls(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
