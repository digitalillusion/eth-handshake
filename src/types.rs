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

/// Wrapper for any [`std::error::Error`]
pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// Transport trait implemented by [`tokio::net::TcpStream`]
pub trait Transport: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Implementation of the [`Transport`]  [`tokio::net::TcpStream`]
impl Transport for TcpStream {}

/// Network representation of an ethereum node
#[derive(Debug)]
pub struct Enode {
    /// The node id
    pub id: Public,
    /// The [`SocketAddr`] of the connection
    pub addr: SocketAddr,
}

/// Implementation of the [`TryInto`] trait to transform a [`String`] into an [`Enode`]
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

/// RPLx data model for Capabilites messaging
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityInfo {
    /// The capability name
    pub name: String,
    /// The capability version
    pub version: usize,
}

/// RPLx encodable trait implementation for Capabilites messaging
impl Encodable for CapabilityInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

/// RPLx decodable trait implementation for Capabilites messaging
impl Decodable for CapabilityInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            name: rlp.val_at(0)?,
            version: rlp.val_at(1)?,
        })
    }
}

/// RPLx hello message
#[derive(Clone, Debug)]
pub struct HelloMessage {
    /// The protocol version
    pub protocol_version: usize,
    /// The version of the client sending the message
    pub client_version: String,
    /// List of Capabilities supported by the client sending the message
    pub capabilities: Vec<CapabilityInfo>,
    /// Port to connect to. 0 means a random available port will be attributed
    pub port: u16,
    /// Peer Id of the peer toward who the message is sent
    pub id: Public,
}

/// RPLx encodable trait for hello message
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

/// RPLx decodable trait for hello message
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
/// RPLx disconnect reason. It's using a byte (u8) representation to match the protocol
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

/// RPLx encodable trait for disconnect reason
impl Encodable for DisconnectReason {
    fn rlp_append(&self, s: &mut RlpStream) {
        let reason: u8 = *self as u8;
        s.append(&reason);
    }
}

/// Implementation of the [`TryInto`] trait to transform a [`u8`] into an [`DisconnectReason`] handling the possible decode error
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

/// Representation of the messages this client exchanges with other peers
#[derive(Clone, Debug)]
pub enum PeerMessage {
    /// Disconnect message, providing a reason for the disconnection
    Disconnect(DisconnectReason),
    /// Ping message
    Ping,
    /// Pong message
    Pong,
    /// All other messages the client may receive from other peers. They must be consumed from the stream
    /// thus they need to be represented here
    Subprotocol,
}

/// Application errors
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The initial connection failed because of an ECIES error
    ConnectionError(EciesError),
    /// Sending an hello message failed because of an ECIES error
    HelloSendError(EciesError),
    /// Receiving an hello message failed because of an io error
    HelloReceiveError(std::io::Error),
    /// Parsing the received hello message failed
    HelloReceiveParse,
    /// Decoding the received hello message failed
    HelloReceiveDecode(DecoderError),
    /// The hello message requested a disconnection
    HelloReceiveDisconnect(DisconnectReason),
    /// This client does not have any capabilities in common with the peer it's trying to connect to
    NoSharedCapabilities,
}

/// Implementation of the [`Display`] trait for [`HandshakeError`]
impl Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Indication of the initiator of a disconnection
#[derive(Debug, Clone, Copy)]
pub enum DisconnectInitiator {
    /// The disconnection was initiated locally
    Local,
    /// The disconnection was initiated remotely
    Remote,
}

/// Signal of disconnection
pub struct DisconnectSignal {
    /// Indication of the initiator
    pub initiator: DisconnectInitiator,
    /// Reason of the disconnection
    pub reason: DisconnectReason,
}
