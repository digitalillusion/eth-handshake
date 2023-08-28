use std::num::TryFromIntError;

use bytes::Bytes;
use ethereum_types::Public;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Current ECIES state of a connection
pub enum ECIESState {
    Auth,
    Ack,
    Header,
    Body,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw egress values for an ECIES protocol
pub enum EgressECIESValue {
    Auth,
    Message(Bytes),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw ingress values for an ECIES protocol
pub enum IngressECIESValue {
    AuthReceive(Public),
    Ack,
    Message(Bytes),
}

#[derive(Debug)]
pub enum EciesError {
    IO(std::io::Error),
    PublicKeyDecryptFailed(secp256k1::Error),
    TagCheckDecryptFailed,
    TagCheckHeaderFailed,
    TagCheckBodyFailed,
    InvalidAuthData,
    InvalidSignatureData(rlp::DecoderError),
    InvalidRecoveryData(secp256k1::Error),
    InvalidRemoteData(rlp::DecoderError),
    InvalidRemotePublicKey(secp256k1::Error),
    InvalidHeader,
    InvalidBodySize(TryFromIntError),
    UnreadableStream,
    InvalidHandshake(IngressECIESValue),
    SubprotocolNotSupported,
}

impl From<std::io::Error> for EciesError {
    fn from(source: std::io::Error) -> Self {
        EciesError::IO(source)
    }
}
