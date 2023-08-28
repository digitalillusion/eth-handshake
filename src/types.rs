use ethereum_types::Public;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::{fmt::Display, net::SocketAddr};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::peer::ecies::EciesError;

/// Protocol version 4 doesn't deal with compression
pub const PROTOCOL_VERSION: usize = 4;

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

pub trait Transport: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl Transport for TcpStream {}

#[derive(Debug)]
pub struct Enode {
    pub id: Public,
    pub addr: SocketAddr,
}

impl TryInto<Enode> for String {
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
pub struct CapabilityInfo {
    pub name: String,
    pub version: usize,
}

impl Encodable for CapabilityInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl Decodable for CapabilityInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            name: rlp.val_at(0)?,
            version: rlp.val_at(1)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<CapabilityInfo>,
    pub port: u16,
    pub id: Public,
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);
        s.append(&self.id);
    }
}

impl Decodable for HelloMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            protocol_version: rlp.val_at(0)?,
            client_version: rlp.val_at(1)?,
            capabilities: rlp.list_at(2)?,
            port: rlp.val_at(3)?,
            id: rlp.val_at(4)?,
        })
    }
}

#[repr(u8)]
/// RLPx disconnect reason.
#[derive(Clone, Copy, Debug)]
pub enum DisconnectReason {
    /// Disconnect requested by the local node or remote peer.
    DisconnectRequested = 0x00,
    /// TCP related error
    TcpSubsystemError = 0x01,
    /// Breach of protocol at the transport or p2p level
    ProtocolBreach = 0x02,
    /// Node has no matching protocols.
    UselessPeer = 0x03,
    /// Either the remote or local node has too many peers.
    TooManyPeers = 0x04,
    /// Already connected to the peer.
    AlreadyConnected = 0x05,
    /// `p2p` protocol version is incompatible
    IncompatibleP2PProtocolVersion = 0x06,
    /// Received a null node identity.
    NullNodeIdentity = 0x07,
    /// Reason when the client is shutting down.
    ClientQuitting = 0x08,
    /// When the received handshake's identify is different from what is expected.
    UnexpectedHandshakeIdentity = 0x09,
    /// The node is connected to itself
    ConnectedToSelf = 0x0a,
    /// Peer or local node did not respond to a ping in time.
    PingTimeout = 0x0b,
    /// Peer or local node violated a subprotocol-specific rule.
    SubprotocolSpecific = 0x10,
}

impl Encodable for DisconnectReason {
    fn rlp_append(&self, s: &mut RlpStream) {
        let reason: u8 = *self as u8;
        s.append(&reason);
    }
}

impl TryFrom<u8> for DisconnectReason {
    type Error = DecoderError;
    fn try_from(value: u8) -> Result<Self, DecoderError> {
        match value {
            0x00 => Ok(DisconnectReason::DisconnectRequested),
            0x01 => Ok(DisconnectReason::TcpSubsystemError),
            0x02 => Ok(DisconnectReason::ProtocolBreach),
            0x03 => Ok(DisconnectReason::UselessPeer),
            0x04 => Ok(DisconnectReason::TooManyPeers),
            0x05 => Ok(DisconnectReason::AlreadyConnected),
            0x06 => Ok(DisconnectReason::IncompatibleP2PProtocolVersion),
            0x07 => Ok(DisconnectReason::NullNodeIdentity),
            0x08 => Ok(DisconnectReason::ClientQuitting),
            0x09 => Ok(DisconnectReason::UnexpectedHandshakeIdentity),
            0x0a => Ok(DisconnectReason::ConnectedToSelf),
            0x0b => Ok(DisconnectReason::PingTimeout),
            0x10 => Ok(DisconnectReason::SubprotocolSpecific),
            _ => Err(DecoderError::Custom("Unknown Disconnect reason")),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PeerMessage {
    Disconnect(DisconnectReason),
    Ping,
    Pong,
    Subprotocol,
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    ConnectionError(EciesError),
    HelloSendError(EciesError),
    HelloReceiveError(std::io::Error),
    HelloReceiveParse,
    HelloReceiveDecode(DecoderError),
    HelloReceiveDisconnect(DisconnectReason),
    NoSharedCapabilities,
}

impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DisconnectInitiator {
    Local,
    LocalForceful,
    Remote,
}

pub struct DisconnectSignal {
    pub initiator: DisconnectInitiator,
    pub reason: DisconnectReason,
}
