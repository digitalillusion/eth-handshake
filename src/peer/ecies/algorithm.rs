use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128, Aes256,
};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use ctr::Ctr64BE;
use ethereum_types::{Public, H128, H256, H512};
use rand::{thread_rng, Rng};
use rlp::{Rlp, RlpStream};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    PublicKey, SecretKey, SECP256K1,
};
use sha3::{Digest, Keccak256};

use super::{
    functions::*,
    mac::{HeaderBytes, MAC},
    types::*,
};

pub struct ECIES {
    secret_key: SecretKey,
    public_key: PublicKey,
    nonce: H256,
    remote_id: Option<Public>,
    remote_init_msg: Option<Bytes>,
    remote_public_key: Option<PublicKey>,
    remote_nonce: Option<H256>,
    remote_ephemeral_public_key: Option<PublicKey>,
    ephemeral_secret_key: SecretKey,
    ephemeral_public_key: PublicKey,
    ephemeral_shared_secret: Option<H256>,
    ingress_aes: Option<Ctr64BE<Aes256>>,
    egress_aes: Option<Ctr64BE<Aes256>>,
    ingress_mac: Option<MAC>,
    egress_mac: Option<MAC>,
    body_size: Option<usize>,
    init_msg: Option<Bytes>,
}

const ECIES_HEADER_LEN: usize = 32;
const PROTOCOL_VERSION: usize = 4;

impl ECIES {
    pub fn new(secret_key: SecretKey, remote_id: Public) -> Result<Self, ECIESError> {
        let nonce = H256::random();
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        let remote_public_key =
            id2pk(remote_id).map_err(|err| ECIESError::InvalidRemotePublicKey(err))?;
        let ephemeral_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let ephemeral_public_key = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key);
        Ok(Self {
            secret_key,
            public_key,
            nonce,
            remote_id: Some(remote_id),
            remote_init_msg: None,
            remote_public_key: Some(remote_public_key),
            remote_nonce: None,
            remote_ephemeral_public_key: None,
            ephemeral_secret_key,
            ephemeral_public_key,
            ephemeral_shared_secret: None,
            ingress_aes: None,
            egress_aes: None,
            ingress_mac: None,
            egress_mac: None,
            body_size: None,
            init_msg: None,
        })
    }

    pub fn remote_id(&self) -> Public {
        self.remote_id.unwrap_or_default().clone()
    }

    pub const fn header_len() -> usize {
        ECIES_HEADER_LEN
    }

    pub fn body_len(&self) -> usize {
        let len = self.body_size.unwrap();
        (if len % 16 == 0 {
            len
        } else {
            (len / 16 + 1) * 16
        }) + 16
    }

    pub fn read_auth(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_auth_unencrypted(unencrypted)
    }

    /// Write an auth message to the given buffer.
    pub fn write_auth(&mut self, buf: &mut BytesMut) {
        let unencrypted = self.create_auth_unencrypted();

        let mut out = buf.split_off(buf.len());
        out.put_u16(0);

        let mut encrypted = out.split_off(out.len());
        self.encrypt_message(&unencrypted, &mut encrypted);

        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        out[..len_bytes.len()].copy_from_slice(&len_bytes);

        out.unsplit(encrypted);

        self.init_msg = Some(Bytes::copy_from_slice(&out));

        buf.unsplit(out);
    }

    pub fn read_ack(&mut self, data: &mut [u8]) -> Result<(), ECIESError> {
        self.remote_init_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_message(data)?;
        self.parse_ack_unencrypted(unencrypted)?;
        self.setup_frame(false);
        Ok(())
    }

    pub fn write_ack(&mut self, out: &mut BytesMut) {
        let unencrypted = self.create_ack_unencrypted();

        let mut buf = out.split_off(out.len());

        buf.put_u16(0);

        let mut encrypted = buf.split_off(buf.len());
        self.encrypt_message(unencrypted.as_ref(), &mut encrypted);
        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        buf.unsplit(encrypted);

        buf[..len_bytes.len()].copy_from_slice(&len_bytes[..]);

        self.init_msg = Some(buf.clone().freeze());
        out.unsplit(buf);

        self.setup_frame(true);
    }

    pub fn read_header(&mut self, data: &mut [u8]) -> Result<usize, ECIESError> {
        let (header_bytes, mac_bytes) = data.split_at_mut(16);
        let header = HeaderBytes::from_mut_slice(header_bytes);
        let mac = H128::from_slice(&mac_bytes[..16]);

        self.ingress_mac.as_mut().unwrap().update_header(header);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckHeaderFailed);
        }

        self.ingress_aes.as_mut().unwrap().apply_keystream(header);
        if header.as_slice().len() < 3 {
            return Err(ECIESError::InvalidHeader);
        }

        let body_size = usize::try_from(header.as_slice().read_uint::<BigEndian>(3)?)
            .map_err(|err| ECIESError::InvalidBodySize(err))?;

        self.body_size = Some(body_size);

        Ok(self.body_size.unwrap())
    }

    pub fn write_header(&mut self, out: &mut BytesMut, size: usize) {
        let mut buf = [0u8; 8];
        BigEndian::write_uint(&mut buf, size as u64, 3);
        let mut header = [0u8; 16];
        header[..3].copy_from_slice(&buf[..3]);
        header[3..6].copy_from_slice(&[194, 128, 128]);

        let mut header = HeaderBytes::from(header);
        self.egress_aes
            .as_mut()
            .unwrap()
            .apply_keystream(&mut header);
        self.egress_mac.as_mut().unwrap().update_header(&header);
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.reserve(ECIES::header_len());
        out.extend_from_slice(header.as_ref());
        out.extend_from_slice(tag.as_bytes());
    }

    pub fn read_body<'a>(&mut self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        let (body, mac_bytes) = data.split_at_mut(data.len() - 16);
        let mac = H128::from_slice(mac_bytes);
        self.ingress_mac.as_mut().unwrap().update_body(body);
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        if check_mac != mac {
            return Err(ECIESError::TagCheckBodyFailed);
        }

        let size = self.body_size.unwrap();
        self.body_size = None;
        let ret = body;
        self.ingress_aes.as_mut().unwrap().apply_keystream(ret);
        Ok(ret.split_at_mut(size).0)
    }

    pub fn write_body(&mut self, out: &mut BytesMut, data: &[u8]) {
        let len = if data.len() % 16 == 0 {
            data.len()
        } else {
            (data.len() / 16 + 1) * 16
        };
        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        self.egress_aes.as_mut().unwrap().apply_keystream(encrypted);
        self.egress_mac.as_mut().unwrap().update_body(encrypted);
        let tag = self.egress_mac.as_mut().unwrap().digest();

        out.extend_from_slice(tag.as_bytes());
    }

    fn decrypt_message<'a>(&self, data: &'a mut [u8]) -> Result<&'a mut [u8], ECIESError> {
        let (auth_data, encrypted) = data.split_at_mut(2);
        let (pubkey_bytes, encrypted) = encrypted.split_at_mut(65);
        let public_key = PublicKey::from_slice(pubkey_bytes)
            .map_err(|err| ECIESError::PublicKeyDecryptFailed(err))?;
        let (data_iv, tag_bytes) = encrypted.split_at_mut(encrypted.len() - 32);
        let (iv, encrypted_data) = data_iv.split_at_mut(16);
        let tag = H256::from_slice(tag_bytes);

        let x = ecdh_x(&public_key, &self.secret_key);
        let mut key = [0u8; 32];
        kdf(x, &[], &mut key);
        let enc_key = H128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let check_tag = hmac_sha256(mac_key.as_ref(), &[iv, encrypted_data], auth_data);
        if check_tag != tag {
            return Err(ECIESError::TagCheckDecryptFailed);
        }

        let decrypted_data = encrypted_data;

        let mut decryptor = Ctr64BE::<Aes128>::new(enc_key.as_ref().into(), (*iv).into());
        decryptor.apply_keystream(decrypted_data);

        Ok(decrypted_data)
    }

    fn parse_auth_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let rlp = Rlp::new(data);
        let mut rlp = rlp.into_iter();

        let sigdata = rlp
            .next()
            .ok_or(ECIESError::InvalidSignatureData(
                rlp::DecoderError::RlpInvalidLength,
            ))?
            .data()
            .map_err(|err| ECIESError::InvalidSignatureData(err))?;
        if sigdata.len() != 65 {
            return Err(ECIESError::InvalidAuthData);
        }
        let signature = RecoverableSignature::from_compact(
            &sigdata[0..64],
            RecoveryId::from_i32(sigdata[64] as i32)
                .map_err(|err| ECIESError::InvalidRecoveryData(err))?,
        )
        .map_err(|err| ECIESError::InvalidRecoveryData(err))?;
        let remote_id = rlp
            .next()
            .ok_or(ECIESError::InvalidRemoteData(
                rlp::DecoderError::RlpInvalidLength,
            ))?
            .as_val::<Public>()
            .map_err(|err| ECIESError::InvalidRemoteData(err))?;
        self.remote_id = Some(remote_id);
        self.remote_public_key = id2pk(remote_id)
            .map_err(|err| ECIESError::InvalidRemotePublicKey(err))
            .ok();
        self.remote_nonce = Some(
            rlp.next()
                .ok_or(ECIESError::InvalidRemoteData(
                    rlp::DecoderError::RlpInvalidLength,
                ))?
                .as_val::<H256>()
                .map_err(|err| ECIESError::InvalidRemoteData(err))?,
        );

        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        self.remote_ephemeral_public_key = Some(
            SECP256K1
                .recover_ecdsa(
                    &secp256k1::Message::from_slice((x ^ self.remote_nonce.unwrap()).as_ref())
                        .unwrap(),
                    &signature,
                )
                .map_err(|err| ECIESError::InvalidRemotePublicKey(err))?,
        );
        self.ephemeral_shared_secret = Some(ecdh_x(
            &self.remote_ephemeral_public_key.unwrap(),
            &self.ephemeral_secret_key,
        ));

        Ok(())
    }

    /// Parse the incoming `ack` message from the given `data` bytes, which are assumed to be
    /// unencrypted. This parses the remote ephemeral pubkey and nonce from the message, and uses
    /// ECDH to compute the shared secret. The shared secret is the x coordinate of the point
    /// returned by ECDH.
    ///
    /// This sets the `remote_ephemeral_public_key` and `remote_nonce`, and
    /// `ephemeral_shared_secret` fields in the ECIES state.
    fn parse_ack_unencrypted(&mut self, data: &[u8]) -> Result<(), ECIESError> {
        let rlp = Rlp::new(data);
        let mut rlp = rlp.into_iter();
        self.remote_ephemeral_public_key = id2pk(
            rlp.next()
                .ok_or(ECIESError::InvalidRemoteData(
                    rlp::DecoderError::RlpInvalidLength,
                ))?
                .as_val::<H512>()
                .map_err(|err| ECIESError::InvalidRemoteData(err))?,
        )
        .ok();
        self.remote_nonce = Some(
            rlp.next()
                .ok_or(ECIESError::InvalidRemoteData(
                    rlp::DecoderError::RlpInvalidLength,
                ))?
                .as_val::<H256>()
                .map_err(|err| ECIESError::InvalidRemoteData(err))?,
        );

        self.ephemeral_shared_secret = Some(ecdh_x(
            &self.remote_ephemeral_public_key.unwrap(),
            &self.ephemeral_secret_key,
        ));
        Ok(())
    }

    fn setup_frame(&mut self, incoming: bool) {
        let mut hasher = Keccak256::new();
        for el in &if incoming {
            [self.nonce, self.remote_nonce.unwrap()]
        } else {
            [self.remote_nonce.unwrap(), self.nonce]
        } {
            hasher.update(el);
        }
        let h_nonce = H256::from(hasher.finalize().as_ref());

        let iv = H128::default();
        let shared_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(h_nonce.0.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        let aes_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(shared_secret.0.as_ref());
            H256::from(hasher.finalize().as_ref())
        };
        self.ingress_aes = Some(Ctr64BE::<Aes256>::new(
            aes_secret.0.as_ref().into(),
            iv.as_ref().into(),
        ));
        self.egress_aes = Some(Ctr64BE::<Aes256>::new(
            aes_secret.0.as_ref().into(),
            iv.as_ref().into(),
        ));

        let mac_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().0.as_ref());
            hasher.update(aes_secret.0.as_ref());
            H256::from(hasher.finalize().as_ref())
        };
        self.ingress_mac = Some(MAC::new(mac_secret));
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.nonce).as_ref());
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update(self.remote_init_msg.as_ref().unwrap());
        self.egress_mac = Some(MAC::new(mac_secret));
        self.egress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.remote_nonce.unwrap()).as_ref());
        self.egress_mac
            .as_mut()
            .unwrap()
            .update(self.init_msg.as_ref().unwrap());
    }

    fn create_auth_unencrypted(&self) -> BytesMut {
        let x = ecdh_x(&self.remote_public_key.unwrap(), &self.secret_key);
        let msg = x ^ self.nonce;
        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_slice(msg.as_bytes()).unwrap(),
                &self.ephemeral_secret_key,
            )
            .serialize_compact();

        let mut sig_bytes = [0_u8; 65];
        sig_bytes[..64].copy_from_slice(&sig);
        sig_bytes[64] = rec_id.to_i32() as u8;
        let mut out = RlpStream::new_list(4);
        out.append(&(&sig_bytes as &[u8]));
        out.append(&pk2id(&self.public_key));
        out.append(&self.nonce);
        out.append(&PROTOCOL_VERSION);

        let mut out = out.out();
        out.resize(out.len() + thread_rng().gen_range(100..=300), 0);
        out
    }

    fn encrypt_message(&self, data: &[u8], out: &mut BytesMut) {
        out.reserve(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + data.len() + 32);

        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &secret_key).serialize_uncompressed(),
        );

        let x = ecdh_x(&self.remote_public_key.unwrap(), &secret_key);
        let mut key = [0u8; 32];
        kdf(x, &[], &mut key);

        let enc_key = H128::from_slice(&key[..16]);
        let mac_key = sha256(&key[16..32]);

        let iv = H128::random();
        let mut encryptor = Ctr64BE::<Aes128>::new(enc_key.as_ref().into(), iv.as_ref().into());

        let mut encrypted = data.to_vec();
        encryptor.apply_keystream(&mut encrypted);

        let total_size: u16 = u16::try_from(65 + 16 + data.len() + 32).unwrap();

        let tag = hmac_sha256(
            mac_key.as_ref(),
            &[iv.as_bytes(), &encrypted],
            &total_size.to_be_bytes(),
        );

        out.extend_from_slice(iv.as_bytes());
        out.extend_from_slice(&encrypted);
        out.extend_from_slice(tag.as_ref());
    }

    fn create_ack_unencrypted(&self) -> BytesMut {
        let mut out = RlpStream::new_list(3);
        out.append(&pk2id(&self.ephemeral_public_key));
        out.append(&self.nonce);
        out.append(&PROTOCOL_VERSION);
        out.out()
    }
}
