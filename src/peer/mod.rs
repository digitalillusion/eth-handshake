use crate::types::Transport;
use bytes::{Bytes, BytesMut};
use futures::sink::SinkExt;
use log::{debug, info};
use rlp::{Rlp, RlpStream};
use secp256k1::SecretKey;
use tokio_stream::StreamExt;

pub mod ecies;

use self::ecies::ECIESStream;
use crate::types::*;

pub struct Peer<T> {
    enode: Enode,
    stream: ECIESStream<T>,
    shared_capabilities: Vec<CapabilityId>,
}

const PROTOCOL_VERSION: usize = 5;

impl<T> Peer<T>
where
    T: Transport,
{
    pub async fn handshake(
        transport: T,
        enode: Enode,
        shared_capabilities: Vec<CapabilityId>,
        secret_key: SecretKey,
    ) -> Result<Self, AnyError> {
        info!("Connecting to enode {:?}", enode.addr);

        let mut stream = ECIESStream::connect(transport, enode.id, secret_key)
            .await
            .map_err(|err| HandshakeError::ConnectionError(err))?;

        let hello = HelloMessage {
            port: 0u16,
            id: enode.id,
            protocol_version: PROTOCOL_VERSION,
            client_version: format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            capabilities: shared_capabilities.clone(),
        };

        let hello_received = Self::exchange_hello(&mut stream, hello).await?;

        Ok(Self {
            enode,
            stream,
            shared_capabilities,
        })
    }

    async fn exchange_hello(
        stream: &mut ECIESStream<T>,
        hello: HelloMessage,
    ) -> Result<HelloMessage, HandshakeError> {
        debug!("Outbound hello message: {:?}", hello);
        let mut outbound_hello = BytesMut::from([0u8; 1].as_ref());
        outbound_hello = {
            let mut s = RlpStream::new_with_buffer(outbound_hello);
            s.append(&hello);
            s.out()
        };
        info!("Sending hello message: {}", hex::encode(&outbound_hello));

        stream
            .send(outbound_hello.freeze())
            .await
            .map_err(|err| HandshakeError::HelloSendError(err))?;

        let hello = stream
            .try_next()
            .await
            .map_err(|err| HandshakeError::HelloReceiveError(err))?
            .ok_or(HandshakeError::HelloReceiveParse)?;
        info!("Receiving hello message: {:?}", hello);

        let message_id_rlp = Rlp::new(&hello[0..1]);
        let message_id = message_id_rlp
            .as_val::<usize>()
            .map_err(|err| HandshakeError::HelloReceiveDecode(err))?;
        match message_id {
            0 => Rlp::new(&hello[1..])
                .as_val::<HelloMessage>()
                .map_err(|err| HandshakeError::HelloReceiveDecode(err)),
            1 => {
                let reason = Rlp::new(&hello[1..])
                    .val_at::<u8>(0)
                    .ok()
                    .and_then(|reason| Some(DisconnectReason::try_from(reason).ok()?))
                    .ok_or(HandshakeError::HelloReceiveDecode(
                        rlp::DecoderError::Custom("Can't decode disconnect reason"),
                    ))?;
                Err(HandshakeError::Disconnect(reason))
            }
            _ => Err(HandshakeError::HelloReceiveDecode(
                rlp::DecoderError::Custom("Wrong message id received"),
            )),
        }
    }

    async fn match_capabilities(
        stream: &mut ECIESStream<T>,
        hello: HelloMessage,
    ) -> Result<(), HandshakeError> {  Ok(())
    }
}
