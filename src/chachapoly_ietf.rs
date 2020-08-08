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
pub c