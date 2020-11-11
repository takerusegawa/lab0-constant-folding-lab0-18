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
    
    /// A helper function for the ChachaPoly-IETF AEAD construction
    pub(in crate) fn chachapoly_auth(tag: &mut[u8], ad: &[u8], data: &[u8], foot: &[u8], key: &[u8]) {
        // Init Poly1305
        let (mut r, mut s, mut u, mut a) = (vec![0; 5], vec![0; 4], vec![0; 5], vec![0; 5]);
        poly1305_init(&mut r, &mut s, &mut u, key);
        
        // Process AD, data and the footer
        poly1305_update(&mut a, &r, &u, ad, false);
        poly1305_update(&mut a, &r, &u, data, false);
        poly1305_update(&mut a, &r, &u, foot, true);
        poly1305_finish(tag, &mut a, &mut s);
    }
}
impl SecKeyGen for Poly1305 {
    fn new_sec_key(&self, buf: &mut[u8], rng: &mut dyn SecureRng) -> Result<usize, Box<dyn Error + 'static>> {
        // Verify input
        vfy_keygen!(POLY1305_KEY => buf);
        
        // Generate key
        rng.random(&mut buf[..POLY1305_KEY])?;
        Ok(POLY1305_KEY)
    }
}
impl Mac for Poly1305 {
    fn info(&self) -> MacInfo {
        MacInfo {
     