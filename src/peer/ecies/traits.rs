use bytes::Bytes;
use futures::{ready, Sink, Stream};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::types::Transport;

use super::{types::*, ECIESStream};

impl<T> Stream for ECIESStream<T>
where
    T: Transport,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.get_mut().stream).poll_next(cx)) {
            Some(Ok(IngressECIESValue::Message(body))) => Poll::Ready(Some(Ok(body))),
            Some(other) => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "ECIES stream protocol error: expected message, received {:?}",
                    other
                ),
            )))),
            None => Poll::Ready(None),
        }
    }
}

impl<Io> Sink<Bytes> for ECIESStream<Io>
where
    Io: Transport,
{
    type Error = ECIESError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).start_send(EgressECIESValue::Message(item))?;

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
