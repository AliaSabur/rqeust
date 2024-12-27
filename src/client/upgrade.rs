use std::pin::Pin;
use std::task::{self, Poll};
use std::{fmt, io};

use crate::util::rt::TokioIo;
use futures_util::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An upgraded HTTP connection.
pub struct Upgraded {
    inner: TokioIo<hyper2::upgrade::Upgraded>,
}

impl AsyncRead for Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl fmt::Debug for Upgraded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upgraded").finish()
    }
}

impl From<hyper2::upgrade::Upgraded> for Upgraded {
    fn from(inner: hyper2::upgrade::Upgraded) -> Self {
        Upgraded {
            inner: TokioIo::new(inner),
        }
    }
}

impl super::response::Response {
    /// Consumes the response and returns a future for a possible HTTP upgrade.
    pub async fn upgrade(self) -> crate::Result<Upgraded> {
        hyper2::upgrade::on(self.res)
            .map_ok(Upgraded::from)
            .map_err(crate::error::upgrade)
            .await
    }
}
