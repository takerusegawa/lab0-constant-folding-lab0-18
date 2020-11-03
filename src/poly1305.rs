use crate::core::poly1305::{ poly1305_init, poly1305_update, poly1305_finish };
use crypto_api::{
    mac::{ MacInfo, Mac },
    rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The size of a Poly1305 key (256 bits/32 bytes)
pub const POLY1305_KEY: usize = 32;
/// The size of a ChaChaPoly authentication tag
pub const POLY1305_TAG: usize = 16;


/// An implementation of [Poly1305](https://tools.ietf.org/html/rfc8439)
pub struct Poly1305;
impl Poly1305 {
    /// Creates a `Mac` instance with `Poly1305` as underlying algorithm
    pub fn mac() -> Box<dyn Mac> {
        Box::new(Self)
    }
    
    /// A hel