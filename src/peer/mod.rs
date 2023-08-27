use log::info;
use secp256k1::SecretKey;
use tokio::net::TcpStream;

mod ecies;

use self::ecies::ECIESStream;
use crate::types::*;

pub struct PeerStream {
    stream: ECIESStream<TcpStream>,
    shared_capabilities: Vec<CapabilityId>,
}

impl PeerStream {
    pub async fn connect(
        enode: Enode,
        shared_capabilities: Vec<CapabilityId>,
        secret_key: SecretKey,
    ) -> Result<Self, AnyError> {
        info!("Connecting to enode {:?}", enode.addr);
        let transport = TcpStream::connect(enode.addr).await?;

        let stream = ECIESStream::connect(transport, enode.id, secret_key).await?;
        Ok(Self {
            stream,
            shared_capabilities,
        })
    }
}
