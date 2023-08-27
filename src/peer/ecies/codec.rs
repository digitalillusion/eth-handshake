use bytes::{Bytes, BytesMut};
use ethereum_types::Public;

use log::{debug, error};
use secp256k1::SecretKey;
use tokio_util::codec::*;

use super::{algorithm::ECIES, types::*};

pub struct ECIESCodec {
    algorithm: ECIES,
    state: ECIESState,
}

impl ECIESCodec {
    pub fn new(secret_key: SecretKey, remote_id: Public) -> Result<Self, ECIESError> {
        Ok(Self {
            algorithm: ECIES::new(secret_key, remote_id)?,
            state: ECIESState::Auth,
        })
    }
}

impl Decoder for ECIESCodec {
    type Item = IngressECIESValue;
    type Error = ECIESError;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                ECIESState::Auth => {
                    debug!("Parsing auth");
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload_size + 2;

                    if buf.len() < total_size {
                        error!("Current len {}, need {}", buf.len(), total_size);
                        return Ok(None);
                    }

                    self.algorithm.read_auth(&mut buf.split_to(total_size))?;

                    self.state = ECIESState::Header;
                    return Ok(Some(IngressECIESValue::AuthReceive(
                        self.algorithm.remote_id(),
                    )));
                }
                ECIESState::Ack => {
                    debug!("Parsing ack with len {}", buf.len());
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload_size + 2;

                    if buf.len() < total_size {
                        error!("Current len {}, need {}", buf.len(), total_size);
                        return Ok(None);
                    }

                    self.algorithm.read_ack(&mut buf.split_to(total_size))?;

                    self.state = ECIESState::Header;
                    return Ok(Some(IngressECIESValue::Ack));
                }
                ECIESState::Header => {
                    debug!("Parsing header");
                    if buf.len() < ECIES::header_len() {
                        error!("Current len {}, need {}", buf.len(), ECIES::header_len());
                        return Ok(None);
                    }

                    self.algorithm
                        .read_header(&mut buf.split_to(ECIES::header_len()))?;

                    self.state = ECIESState::Body;
                }
                ECIESState::Body => {
                    debug!("Parsing body");
                    if buf.len() < self.algorithm.body_len() {
                        return Ok(None);
                    }

                    let mut data = buf.split_to(self.algorithm.body_len());
                    let ret = Bytes::copy_from_slice(self.algorithm.read_body(&mut data)?);

                    self.state = ECIESState::Header;
                    return Ok(Some(IngressECIESValue::Message(ret)));
                }
            }
        }
    }
}

impl Encoder<EgressECIESValue> for ECIESCodec {
    type Error = ECIESError;

    fn encode(&mut self, item: EgressECIESValue, buf: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            EgressECIESValue::Auth => {
                debug!("Encoding Auth");
                self.state = ECIESState::Ack;
                self.algorithm.write_auth(buf);
                Ok(())
            }
            EgressECIESValue::Ack => {
                debug!("Encoding Ack");
                self.state = ECIESState::Header;
                self.algorithm.write_ack(buf);
                Ok(())
            }
            EgressECIESValue::Message(data) => {
                debug!("Encoding Message");
                self.algorithm.write_header(buf, data.len());
                self.algorithm.write_body(buf, &data);
                Ok(())
            }
        }
    }
}
