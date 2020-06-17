use crypto_api_chachapoly::{ ChachaPolyIetf, XChachaPoly, crypto_api::cipher::AeadCipher };
use sodiumoxide::crypto::{
    stream::salsa20,
    aead::{ chacha20poly1305_ietf, xchacha20poly1305_ietf }
};
use hex::ToHex;
use std::{
    env, thread, ops::Range, str::FromStr, time::Duration,
    sync::atomic::{ AtomicU64, Ordering::Relaxed }
};


/// Set jemalloc as allocator if specified
#[cfg(feature = "jemalloc")]
    #[global_allocator] static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// An atomic test counter
static COUNTER: AtomicU64 = AtomicU64::new(0);


/// A fast but still secure RNG
struct SecureRng {
    seed: salsa20::Key,
    ctr: u64
}
impl SecureRng {
    /// Creates a new RNG
    pub fn new() -> Self {
        Self{ seed: salsa20::gen_key(), ctr: 0 }
    }
    
    /// Fills `buf` with secure random byt