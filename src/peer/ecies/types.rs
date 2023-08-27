use std::{num::TryFromIntError, fmt::Display};

use bytes::Bytes;
use ethereum_types::Public;
use thiserror::Error;

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
    Ack,
    Message(Bytes),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw ingress values for an ECIES protocol
pub enum IngressECIESValue {
    AuthReceive(Public),
    Ack,
    Message(Bytes),
}

#[derive(Debug, Error)]
pub enum ECIESError {
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
}

impl From<std::io::Error> for ECIESError {
    fn from(source: std::io::Error) -> Self {
        ECIESError::IO(source).into()
    }
}

impl Display for ECIESError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}