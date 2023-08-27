use secp256k1::SecretKey;

use crate::{peer::Peer, types::*};

use tokio::net::TcpStream;

pub struct NetworkService {
    capabilities: Vec<CapabilityId>,
    secret_key: SecretKey,
}

impl NetworkService {
    pub fn new(capabilities: Vec<CapabilityId>, secret_key: SecretKey) -> Self {
        Self {
            capabilities,
            secret_key,
        }
    }

    pub async fn connect(&self, enode: Enode) -> Result<Peer<TcpStream>, AnyError> {
        let transport = TcpStream::connect(enode.addr).await?;
        Peer::handshake(transport, enode, self.capabilities.clone(), self.secret_key).await
    }
}
