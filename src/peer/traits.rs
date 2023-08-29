use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, Stream};
use rlp::{Rlp, RlpStream};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tracing::{debug, info};

use crate::types::{DisconnectReason, PeerMessage, Transport};

use super::{ecies::EciesError, Peer};

/// Implement the [`Stream`] trait for [`Peer<T>`].
///
/// This trait is used to poll the peer's [`Stream`] for [`PeerMessage`]s that were received from the remote peer
///
/// ### See also
/// [`futures::StreamExt::split`] in order to be able to obtain a [`Sink`] and [`Stream`] interface
impl<T> Stream for Peer<T>
where
    T: Transport,
{
    type Item = Result<PeerMessage, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();

        // Avoid enqueuing messages for a disconnecting peer
        if s.disconnecting {
            return Poll::Ready(None);
        }

        match ready!(Pin::new(&mut s.stream).poll_next(cx)) {
            Some(Ok(val)) => {
                debug!("Received peer message: {}", hex::encode(&val));
                // RLPx decoding of the received message
                let message_id_rlp = Rlp::new(&val[0..1]);
                let message_id: Result<usize, rlp::DecoderError> = message_id_rlp.as_val();
                let data = Bytes::copy_from_slice(&val[1..]);

                match message_id {
                    Ok(0x01) => {
                        s.disconnecting = true;
                        match DisconnectReason::try_from(data[0]).ok() {
                            Some(reason) => Poll::Ready(Some(Ok(PeerMessage::Disconnect(reason)))),
                            _ => Poll::Ready(Some(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "Peer disconnected with malformed message: {}",
                                    hex::encode(data)
                                ),
                            )))),
                        }
                    }
                    Ok(0x02) => {
                        info!("Received ping message data {:?}", data);
                        Poll::Ready(Some(Ok(PeerMessage::Ping)))
                    }
                    Ok(0x03) => {
                        info!("Received pong message");
                        Poll::Ready(Some(Ok(PeerMessage::Pong)))
                    }
                    Ok(message_id) => {
                        if message_id < 10 {
                            info!("Received unknown reserved message");
                            return Poll::Ready(Some(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "unhandled message",
                            ))));
                        }
                        Poll::Ready(Some(Ok(PeerMessage::Subprotocol)))
                    }
                    _ => Poll::Ready(None),
                }
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

/// Implement the [`Sink`] trait for [`Peer<T>`].
///
/// This trait is used to send [`PeerMessage`]s to the peer's [`Sink`], which in turn send them to the remote peer
///
/// ### See also
/// [`futures::StreamExt::split`] in order to be able to obtain a [`Sink`] and [`Stream`] interface
impl<Io> Sink<PeerMessage> for Peer<Io>
where
    Io: Transport,
{
    type Error = EciesError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, message: PeerMessage) -> Result<(), Self::Error> {
        let this = self.get_mut();

        let (message_id, payload) = match message {
            PeerMessage::Disconnect(reason) => (0x01u8, rlp::encode(&reason).into()),
            PeerMessage::Ping => {
                info!("Sending ping message");
                (0x02u8, rlp::EMPTY_LIST_RLP.to_vec())
            }
            PeerMessage::Pong => {
                info!("Sending pong message");
                (0x03u8, rlp::EMPTY_LIST_RLP.to_vec())
            }
            PeerMessage::Subprotocol => {
                return Err(EciesError::SubprotocolNotSupported);
            }
        };

        // RLPX encoding of the message to send
        let mut s = RlpStream::new_with_buffer(BytesMut::with_capacity(2 + payload.len()));
        s.append(&message_id);
        let mut msg = s.out();

        msg.extend_from_slice(&payload);

        Pin::new(&mut this.stream).start_send(msg.freeze())?;

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
