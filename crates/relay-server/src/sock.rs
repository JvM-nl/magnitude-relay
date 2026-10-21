//! A client connection's socket: plain TCP, TCP under TLS, or a Unix socket (a
//! web server on the same machine, which saves both sides the TCP stack).
//!
//! The reactor's connection code is written against this type so that HTTPS needs
//! no second copy of it. The plain variant is a bare `TcpStream`; every method here
//! is one `match` and a call, so a plain connection does exactly what it did before
//! TLS existed: same syscalls, same buffers, no allocation, no dynamic dispatch.

use relay_tls::TlsConn;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};

/// How a TLS connection is accepted: the certificates and protocol settings.
pub type TlsConfig = Arc<relay_tls::ServerConfig>;

/// A connection waiting for its reactor: the socket, the peer, and the TLS settings
/// when it arrived on the HTTPS listener (`None` otherwise).
pub type Incoming = (Stream, SocketAddr, Option<TlsConfig>);

/// An accepted socket, before its reactor adopts it.
pub enum Stream {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

/// One `recv` that, when it comes back short, also tells tokio the socket is
/// drained: a stream socket returns less than asked only when it has nothing
/// more. tokio forgets a socket's readiness only on `WouldBlock`, so every read
/// that found data was followed by one that found none (1.6 empty reads a
/// query, as many as reads with data). tokio clears just the readiness it saw
/// at the start, so data arriving meanwhile still wakes the connection.
macro_rules! drain_read {
    ($s:expr, $buf:expr) => {{
        let (s, buf): (_, &mut [u8]) = ($s, $buf);
        let fd = std::os::fd::AsRawFd::as_raw_fd(s);
        let mut got = 0;
        let r = s.try_io(tokio::io::Interest::READABLE, || {
            // SAFETY: `buf` is valid for writes of its length.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            got = n as usize;
            if got > 0 && got < buf.len() {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(got)
            }
        });
        match r {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && got > 0 => Ok(got),
            r => r,
        }
    }};
}

/// The longest a TLS handshake may take before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub enum Sock {
    Plain(TcpStream),
    /// Boxed so the common variant stays small.
    Tls(Box<TlsConn>),
    Unix(UnixStream),
}

impl Sock {
    /// The socket for a new connection, on the reactor's runtime: as it is, or
    /// after the TLS handshake. `None` when it cannot be adopted, or the handshake
    /// fails, times out, or was only a CA validating a challenge.
    pub async fn open(s: Stream, tls: Option<TlsConfig>) -> Option<Sock> {
        let s = match s {
            Stream::Tcp(s) => TcpStream::from_std(s),
            Stream::Unix(s) => return UnixStream::from_std(s).inspect_err(|e| eprintln!("cannot adopt connection: {e}")).ok().map(Sock::Unix),
        };
        let s = s.inspect_err(|e| eprintln!("cannot adopt connection: {e}")).ok()?;
        let Some(config) = tls else { return Some(Sock::Plain(s)) };
        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, TlsConn::accept(s, config)).await {
            Ok(Ok(c)) => Some(Sock::Tls(Box::new(c))),
            _ => None,
        }
    }

    /// Unencrypted: output can be written as it is, shared bodies spliced in.
    #[inline]
    pub fn is_clear(&self) -> bool {
        !matches!(self, Sock::Tls(_))
    }

    /// Resolves when a [`try_read`](Self::try_read) is worth making. Cancel-safe.
    #[inline]
    pub async fn readable(&self) -> io::Result<()> {
        match self {
            Sock::Plain(s) => s.readable().await,
            Sock::Tls(t) => t.readable().await,
            Sock::Unix(s) => s.readable().await,
        }
    }

    /// Reads without waiting; `WouldBlock` when there is nothing, `Ok(0)` at the end.
    #[inline]
    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Sock::Plain(s) => drain_read!(s, buf),
            // Reads until the socket would block (see `TlsConn::try_read`).
            Sock::Tls(t) => t.try_read(buf),
            Sock::Unix(s) => drain_read!(s, buf),
        }
    }

    /// Writes all of `buf`. (Named like the `AsyncWriteExt` method it stands in for:
    /// that one would leave TLS output buffered, this one does not.)
    #[inline]
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Sock::Plain(s) => s.write_all(buf).await,
            Sock::Tls(t) => t.send(buf).await,
            Sock::Unix(s) => s.write_all(buf).await,
        }
    }
}

impl AsyncRead for Sock {
    #[inline]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Sock::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Sock::Tls(t) => Pin::new(&mut **t).poll_read(cx, buf),
            Sock::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Sock {
    #[inline]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Sock::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Sock::Tls(t) => Pin::new(&mut **t).poll_write(cx, buf),
            Sock::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Sock::Plain(s) => Pin::new(s).poll_flush(cx),
            Sock::Tls(t) => Pin::new(&mut **t).poll_flush(cx),
            Sock::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Sock::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Sock::Tls(t) => Pin::new(&mut **t).poll_shutdown(cx),
            Sock::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plain variant is the common one: the enum may add a tag to a bare socket
    /// but nothing more, and TLS state lives behind the box.
    #[test]
    fn a_plain_socket_costs_what_it_did_before() {
        let (sock, bare) = (std::mem::size_of::<Sock>(), std::mem::size_of::<TcpStream>());
        assert!(sock <= bare + std::mem::size_of::<usize>(), "{sock} vs {bare}");
    }
}
