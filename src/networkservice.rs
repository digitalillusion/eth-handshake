use log::info;
use secp256k1::SecretKey;
use tokio::net::TcpStream;

use crate::types::{CapabilityId, Enode, PeerStream};

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

    pub async fn connect(&self, enode: Enode) -> Result<PeerStream, std::io::Error> {
        info!("Connecting to enode {:?}", enode.addr);
        let transport = TcpStream::connect(enode.addr).await?;

        Ok(PeerStream::new(transport, self.capabilities.clone()))
    }
}
