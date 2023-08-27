use secp256k1::SecretKey;

use crate::{peer::PeerStream, types::*};

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

    pub async fn connect(&self, enode: Enode) -> Result<PeerStream, AnyError> {
        PeerStream::connect(enode, self.capabilities.clone(), self.secret_key).await
    }
}
