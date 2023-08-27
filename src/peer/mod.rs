use std::collections::HashSet;

use crate::types::Transport;
use bytes::BytesMut;
use futures::sink::SinkExt;
use tracing::{debug, info, error, instrument};
use rlp::{Rlp, RlpStream};
use secp256k1::SecretKey;
use tokio_stream::StreamExt;

pub mod ecies;

use self::ecies::ECIESStream;
use crate::types::*;

pub struct Peer<T> {
    enode: Enode,
    stream: ECIESStream<T>,
    capabilities: Vec<CapabilityId>,
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
        info!("Connecting to enode {} (remote_id={})", enode.addr, enode.id);

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

        let capabilities =
            Self::match_capabilities(shared_capabilities, hello_received)?;

        Ok(Self {
            enode,
            stream,
            capabilities,
        })
    }

    #[instrument(skip_all, fields(remote_id=&*format!("{}", hello.id)))]
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

    #[instrument(skip_all, fields(remote_id=&*format!("{}", hello_received.id)))]
    fn match_capabilities(
        required: Vec<CapabilityId>,
        hello_received: HelloMessage,
    ) -> Result<Vec<CapabilityId>, HandshakeError> {
        let required: HashSet<CapabilityId> = required.into_iter().collect();
        let offered: HashSet<CapabilityId> = hello_received.capabilities.into_iter().collect();
        let intersection: Vec<CapabilityId> = required.intersection(&offered)
        .map(|el| el.clone()).collect();
        if intersection.is_empty() {
            error!("No shared capabilities, disconnecting.");
            Err(HandshakeError::Disconnect(DisconnectReason::UselessPeer))
        } else {
            info!("Found {} shared capabilities", intersection.len());
            Ok(intersection)
        }
    }
}
