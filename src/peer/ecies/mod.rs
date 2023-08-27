mod algorithm;
mod codec;
mod functions;
mod mac;
mod types;

use ethereum_types::Public;
use log::{debug, info};
use secp256k1::SecretKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt;
use tokio_util::codec::*;
use futures::sink::SinkExt;

use self::{codec::ECIESCodec, types::*};

use types::{EgressECIESValue, IngressECIESValue};

pub struct ECIESStream<T> {
    stream: Framed<T, ECIESCodec>,
    remote_id: Public,
}

impl<T> ECIESStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    pub async fn connect(
        transport: T,
        remote_id: Public,
        secret_key: SecretKey,
    ) -> Result<Self, ECIESError>
    {
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

        info!("Parsing ECIES ack ...");
        if matches!(msg, IngressECIESValue::Ack) {
            Ok(Self {
                stream: transport,
                remote_id,
            })
        } else {
            Err(ECIESError::InvalidHandshake(msg))
        }
    }
}
