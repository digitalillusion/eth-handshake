use ethereum_types::{Public, H256};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Hashes the input data with SHA256.
pub fn sha256(data: &[u8]) -> H256 {
    H256::from(Sha256::digest(data).as_ref())
}

/// Produces a HMAC_SHA256 digest of the `input_data` and `auth_data` with the given `key`.
/// This is done by accumulating each slice in `input_data` into the HMAC state, then accumulating
/// the `auth_data` and returning the resulting digest.
pub(crate) fn hmac_sha256(key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    H256::from_slice(&hmac.finalize().into_bytes())
}

/// Computes the shared secret with ECDH and strips the y coordinate after computing the shared
/// secret.
///
/// This uses the given remote public key and local (ephemeral) secret key to [compute a shared
/// secp256k1 point](secp256k1::ecdh::shared_secret_point) and slices off the y coordinate from the
/// returned pair, returning only the bytes of the x coordinate as a [`H256`].
pub fn ecdh_x(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    H256::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[..32])
}

pub fn kdf(secret: H256, s1: &[u8], dest: &mut [u8]) {
    // SEC/ISO/Shoup specify counter size SHOULD be equivalent
    // to size of hash output, however, it also notes that
    // the 4 bytes is okay. NIST specifies 4 bytes.
    let mut ctr = 1_u32;
    let mut written = 0_usize;
    while written < dest.len() {
        let mut hasher = Sha256::default();
        let ctrs = [
            (ctr >> 24) as u8,
            (ctr >> 16) as u8,
            (ctr >> 8) as u8,
            ctr as u8,
        ];
        hasher.update(ctrs);
        hasher.update(secret.as_bytes());
        hasher.update(s1);
        let d = hasher.finalize();
        dest[written..(written + 32)].copy_from_slice(&d);
        written += 32;
        ctr += 1;
    }
}

/// Converts a [PeerId] to a [secp256k1::PublicKey] by prepending the [PeerId] bytes with the
/// SECP256K1_TAG_PUBKEY_UNCOMPRESSED tag.
pub(crate) fn id2pk(id: Public) -> Result<PublicKey, secp256k1::Error> {
    // NOTE: H512 is used as a PeerId not because it represents a hash, but because 512 bits is
    // enough to represent an uncompressed public key.
    let mut s = [0u8; 65];
    // SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04
    // see: https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L211
    s[0] = 4;
    s[1..].copy_from_slice(id.as_bytes());
    PublicKey::from_slice(&s)
}

/// Converts a [secp256k1::PublicKey] to a [PeerId] by stripping the
/// SECP256K1_TAG_PUBKEY_UNCOMPRESSED tag and storing the rest of the slice in the [PeerId].
pub fn pk2id(pk: &PublicKey) -> Public {
    Public::from_slice(&pk.serialize_uncompressed()[1..])
}
