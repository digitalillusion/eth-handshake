use ethereum_types::Public;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

pub struct Enode {
    pub id: Public,
    pub addr: SocketAddr,
}

impl TryInto<Enode> for &str {
    type Error = AnyError;

    fn try_into(self) -> Result<Enode, Self::Error> {
        const PREFIX: &str = "enode://";

        let (prefix, data) = self.split_at(PREFIX.len());
        if prefix != PREFIX {
            return Err("Not an enode".into());
        }

        let mut parts = data.split('@');
        let id = parts.next().ok_or("Failed to read remote ID")?.parse()?;
        let addr = parts.next().ok_or("Failed to read address")?.parse()?;

        Ok(Enode { id, addr })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId {
    pub name: String,
    pub version: usize,
}

pub struct ECIESStream {
    transport: TcpStream,
}

pub struct PeerStream {
    stream: ECIESStream,
    shared_capabilities: Vec<CapabilityId>,
}

impl PeerStream {
    pub fn new(transport: TcpStream, shared_capabilities: Vec<CapabilityId>) -> Self {
        let stream = ECIESStream { transport };
        Self {
            stream,
            shared_capabilities,
        }
    }
}