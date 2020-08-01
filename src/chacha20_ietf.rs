
use crate::core::chacha20::chacha20_ietf_block;
use crypto_api::{
    cipher::{ CipherInfo, Cipher },
    rng::{ SecureRng, SecKeyGen }
};
use std::{ cmp::min, error::Error };


/// The maximum amount of bytes that can be processed with one key/nonce combination
#[cfg(target_pointer_width = "64")]
pub const CHACHA20_MAX: usize = 4_294_967_296 * 64; // 2^32 * BLOCK_SIZE
/// The maximum amount of bytes that can be processed with one key/nonce combination