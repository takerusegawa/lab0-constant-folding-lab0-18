
use crate::{
    chacha20_ietf::CHACHA20_KEY,
    core::chacha20::{ hchacha20_hash, chacha20_block }
};
use crypto_api::{
    cipher::{ CipherInfo, Cipher },
    rng::{ SecureRng, SecKeyGen }
};
use std::{ cmp::min, error::Error };


/// The maximum amount of bytes that can be processed by this implementation with one key/nonce
/// combination
pub const XCHACHA20_MAX: usize = usize::max_value();
