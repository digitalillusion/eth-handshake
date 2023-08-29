use std::collections::HashSet;

use crate::{peer::functions::pk2id, types::Transport};
use bytes::BytesMut;
use futures::sink::SinkExt;
use rlp::{Rlp, RlpStream};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, instrument};

pub mod ecies;
mod functions;
mod traits;

use self::ecies::EciesStream;
use crate::types::*;

/// Structure representing a remote peer connection
///
/// ### Type arguments
///  - T: The type of the transport to use for the [`EciesStream`], must implement the [`Transport`] trait
pub struct Peer<T> {
    /// The [`EciesStream`] that was authorized and connect
    stream: EciesStream<T>,
    /// A boolean flag that indicates if a disconnection was initiated
    disconnecting: bool,
}

impl<T> Peer<T>
where
    T: Transport,
{
    /// Perform an handshake toward the other peer
    ///
    /// ### Arguments
    ///  - transport: The transport to use for the [`EciesStream`]
    ///  - enode: The [`Enode`] to connect to
    ///  - shared_capabilities: The collection of [`CapabilityInfo`] to probe for availability on the other peer
    ///  - secret_key: The secret key of this client
    ///
    /// ### Return
    /// Result of `Peer<T>` or [`AnyError`]
    pub async fn handshake(
        transport: T,
        enode: Enode,
        shared_capabilities: Vec<CapabilityInfo>,
        secret_key: SecretKey,
    ) -> Result<Self, AnyError> {
        info!(
            "Connecting to enode {} (remote_id={})",
            enode.addr, enode.id
        );

        let mut stream = EciesStream::connect(transport, enode.id, secret_key)
            .await
            .map_err(HandshakeError::ConnectionError)?;

        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let hello = HelloMessage {
            port: 0u16,
            id: pk2id(&public_key),
            protocol_version: PROTOCOL_VERSION,
            client_version: format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            capabilities: shared_capabilities.clone(),
        };

        let hello_received = Self::exchange_hello(&mut stream, hello).await?;
        info!("Received hello message: {:?}", hello_received);

        Self::match_capabilities(shared_capabilities, hello_received)?;

        Ok(Self {
            stream,
            disconnecting: false,
        })
    }

    /// Performs the exchange of [`HelloMessage`]
    #[instrument(skip_all, fields(remote_id=&*format!("{}", hello.id)))]
    async fn exchange_hello(
        stream: &mut EciesStream<T>,
        hello: HelloMessage,
    ) -> Result<HelloMessage, HandshakeError> {
        info!("Sending hello message: {:?}", hello);
        let mut outbound_hello = BytesMut::new();
        outbound_hello = {
            let mut s = RlpStream::new_with_buffer(outbound_hello);
            s.append(&0_usize);
            s.out()
        };
        outbound_hello = {
            let mut s = RlpStream::new_with_buffer(outbound_hello);
            s.append(&hello);
            s.out()
        };
        debug!("Outbound hello message: {}", hex::encode(&outbound_hello));

        stream
            .send(outbound_hello.freeze())
            .await
            .map_err(HandshakeError::HelloSendError)?;

        let hello = stream
            .try_next()
            .await
            .map_err(HandshakeError::HelloReceiveError)?
            .ok_or(HandshakeError::HelloReceiveParse)?;
        debug!("Receiving hello message: {:?}", hello);

        let message_id_rlp = Rlp::new(&hello[0..1]);
        let message_id = message_id_rlp
            .as_val::<usize>()
            .map_err(HandshakeError::HelloReceiveDecode)?;
        match message_id {
            0 => Rlp::new(&hello[1..])
                .as_val::<HelloMessage>()
                .map_err(HandshakeError::HelloReceiveDecode),
            1 => {
                let reason = Rlp::new(&hello[1..])
                    .val_at::<u8>(0)
                    .ok()
                    .and_then(|reason| DisconnectReason::try_from(reason).ok())
                    .ok_or(HandshakeError::HelloReceiveDecode(
                        rlp::DecoderError::Custom("Can't decode disconnect reason"),
                    ))?;
                Err(HandshakeError::HelloReceiveDisconnect(reason))
            }
            _ => Err(HandshakeError::HelloReceiveDecode(
                rlp::DecoderError::Custom("Wrong message id received"),
            )),
        }
    }

    /// Checks that the peers have shared capabilities
    #[instrument(skip_all, fields(remote_id=&*format!("{}", hello_received.id)))]
    fn match_capabilities(
        required: Vec<CapabilityInfo>,
        hello_received: HelloMessage,
    ) -> Result<(), HandshakeError> {
        let required: HashSet<CapabilityInfo> = required.into_iter().collect();
        let offered: HashSet<CapabilityInfo> = hello_received.capabilities.into_iter().collect();
        let intersection: Vec<CapabilityInfo> = required.intersection(&offered).cloned().collect();
        if intersection.is_empty() {
            error!("No shared capabilities, disconnecting.");
            Err(HandshakeError::NoSharedCapabilities)
        } else {
            info!("Found {} shared capabilities", intersection.len());
            Ok(())
        }
    }
}
