use crate::{ ChachaPolyError, ChaCha20Ietf, Poly1305 };
use crypto_api::{
    cipher::{ CipherInfo, Cipher, AeadCipher },
    rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "64")]
pub const CHACHAPOLY_MAX: usize = (4_294_967_296 - 1) * 64; // (2^32 - 1) * BLOCK_SIZE
/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "32")]
pub const CHACHAPOLY_MAX: usize = usize::max_value() - 16; // 2^32 - 1 - 16

/// The size of a ChaChaPoly key (256 bits/32 bytes)
pub const CHACHAPOLY_KEY: usize = 32;
/// The size of a ChaChaPoly nonce (96 bits/12 bytes)
pub const CHACHAPOLY_NONCE: usize = 12;
/// The size of a ChaChaPoly authentication tag
pub const CHACHAPOLY_TAG: usize = 16;


/// Encrypts `data` in place and authenticates it with `ad` into `tag` using `key` and `nonce`
pub fn chachapoly_seal(data: &mut[u8], tag: &mut[u8], ad: &[u8], key: &[u8], nonce: &[u8]) {
    // Encrypt the data
    ChaCha20Ietf::xor(key, nonce, 1, data);
    
    // Create the footer
    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
    
    // Compute the Poly1305 key and the authentication tag
    let mut pkey = vec![0; 32];
    ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(tag, ad, data, &foot, &pkey);
}
/// Validates `data` with `ad` and decrypts it in place using `key` and `nonce`
pub fn chachapoly_open(data: &mut[u8], tag: &[u8], ad: &[u8], key: &[u8], nonce: &[u8])
    -> Result<(), Box<dyn Error + 'static>>
{
    // Create the footer
    let mut foot = Vec::with_capacity(16);
    foot.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    foot.extend_from_slice(&(data.len() as u64).to_le_bytes());
    
    // Compute the Poly1305 key and the authentication tag
    let (mut pkey, mut vfy_tag) = (vec![0; 32], vec![0; 16]);
    ChaCha20Ietf::xor(key, nonce, 0, &mut pkey);
    Poly1305::chachapoly_auth(&mut vfy_tag, ad, data, &foot, &pkey);
    
    // Validate the recomputed and the original tag
    Ok(match eq_ct!(&tag, &vfy_tag) {
        true => ChaCha20Ietf::xor(key, nonce, 1, data),
        false => Err(ChachaPolyError::InvalidData)?
    })
}


/// An implementation of the
/// [ChachaPoly-IETF AEAD-construction](https://too