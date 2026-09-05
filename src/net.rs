use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Either a plain TCP stream or one wrapped in TLS, so the proxy can relay
/// LDAP frames the same way regardless of which transport a given connection
/// (client-facing or upstream) negotiated.
pub enum MaybeTlsStream<T> {
    Plain(TcpStream),
    Tls(T),
}

impl<T: AsyncRead + Unpin> AsyncRead for MaybeTlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_flush(cx),
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            MaybeTlsStream::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}
