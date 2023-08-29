mod algorithm;
mod codec;
mod mac;
mod types;
mod traits;

use ethereum_types::Public;
use futures::sink::SinkExt;
use secp256k1::SecretKey;
use tokio_stream::StreamExt;
use tokio_util::codec::*;
use tracing::{debug, info, instrument};

use crate::types::Transport;

use self::codec::EciesCodec;

use types::{EgressECIESValue, IngressECIESValue};

pub use types::EciesError;

/// Structure representing an ECIES stream.
/// The transport is framed with a [`EciesCodec`] that provides interpretation of the raw bytes
/// 
/// ### Type arguments
///  - T: The type of the transport to use for the `EciesStream`, must implement the [`Transport`] trait
pub struct EciesStream<T> {
    stream: Framed<T, EciesCodec>,
}

impl<T> EciesStream<T>
where
    T: Transport,
{
    /// Perform a connection the other peer
    /// 
    /// ### Arguments
    ///  - transport: The transport to use for the [`EciesStream`]
    ///  - remote_id: The [`Public`] key of the other peer
    ///  - secret_key: The secret key of this client
    /// 
    /// ### Return
    /// Result of `EciesStream<T>` or [`eth-handshake::types::AnyError`]
    #[instrument(skip_all, fields(remote_id=&*format!("{}", remote_id)))]
    pub async fn connect(
        transport: T,
        remote_id: Public,
        secret_key: SecretKey,
    ) -> Result<Self, EciesError> {
        let codec = EciesCodec::new(secret_key, remote_id)?;

        let mut transport = codec.framed(transport);

        info!("Sending ECIES auth ...");
        transport.send(EgressECIESValue::Auth).await?;

        info!("Waiting for ECIES ack ...");

        let msg = transport.try_next().await?;

        // `Framed` returns `None` if the underlying stream is no longer readable, and the codec is
        // unable to decode another message from the (partially filled) buffer. This usually happens
        // if the remote drops the TcpStream.
        let msg: IngressECIESValue = msg.ok_or(EciesError::UnreadableStream)?;

        debug!("Parsing ECIES ack ...");
        if matches!(msg, IngressECIESValue::Ack) {
            info!("Received ECIES ack ...");
            Ok(Self { stream: transport })
        } else {
            Err(EciesError::InvalidHandshake(msg))
        }
    }
}