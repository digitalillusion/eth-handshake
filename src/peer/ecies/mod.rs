mod algorithm;
mod codec;
mod functions;
mod mac;
mod types;

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use ethereum_types::Public;
use futures::{ready, sink::SinkExt, Sink, Stream};
use log::{debug, info};
use secp256k1::SecretKey;
use tokio_stream::StreamExt;
use tokio_util::codec::*;

use crate::types::Transport;

use self::codec::ECIESCodec;

use types::{EgressECIESValue, IngressECIESValue};

pub use types::ECIESError;

pub struct ECIESStream<T> {
    stream: Framed<T, ECIESCodec>,
    remote_id: Public,
}

impl<T> ECIESStream<T>
where
    T: Transport,
{
    pub async fn connect(
        transport: T,
        remote_id: Public,
        secret_key: SecretKey,
    ) -> Result<Self, ECIESError> {
        let codec = ECIESCodec::new(secret_key, remote_id)?;

        let mut transport = codec.framed(transport);

        info!("Sending ECIES auth ...");
        transport.send(EgressECIESValue::Auth).await?;

        info!("Waiting for ECIES ack ...");

        let msg = transport.try_next().await?;

        // `Framed` returns `None` if the underlying stream is no longer readable, and the codec is
        // unable to decode another message from the (partially filled) buffer. This usually happens
        // if the remote drops the TcpStream.
        let msg: IngressECIESValue = msg.ok_or(ECIESError::UnreadableStream)?;

        debug!("Parsing ECIES ack ...");
        if matches!(msg, IngressECIESValue::Ack) {
            info!("Received ECIES ack ...");
            Ok(Self {
                stream: transport,
                remote_id,
            })
        } else {
            Err(ECIESError::InvalidHandshake(msg))
        }
    }
}

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
