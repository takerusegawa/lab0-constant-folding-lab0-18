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
    
    /// Fills `buf` with secure random bytes
    pub fn random(&mut self, buf: &mut[u8]) {
        // Create nonce
        let nonce = salsa20::Nonce::from_slice(&self.ctr.to_be_bytes()).unwrap();
        self.ctr += 1;
        
        // Create random bytes
        buf.iter_mut().for_each(|b| *b = 0);
        salsa20::stream_xor_inplace(buf, &nonce, &self.seed);
    }
    /// Creates a `len`-sized vector filled with secure random bytes
    pub fn random_vec(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        self.random(&mut buf);
        buf
    }
    /// Computes a secure random number within `range`
    pub fn random_range(&mut self, range: Range<u128>) -> u128 {
        // Compute the bucket size and amount
        let bucket_size = range.end - range.start;
        let bucket_count = u128::max_value() / bucket_size;
        
        // Compute the number
        let mut num = [0; 16];
        loop {
            // Generates a random number
            self.random(&mut num);
            let num = u128::from_ne_bytes(num);
            
            // Check if the number falls into the
            if num < bucket_size * bucket_count {
                return (num % bucket_size) + range.start
            }
        }
    }
    /// Creates a vec with random sized length within `range` filled with secure random data
    pub fn random_len_vec(&mut self, range: Range<usize>) -> Vec<u8> {
        let range = (range.start as u128)..(range.end as u128);
        let len = self.random_range(range) as usize;
        self.random_vec(len)
    }
}


/// A `ChachaPolyIetf` test vector
struct ChachaPolyIetfTV {
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    ad: Vec<u8>
}
impl ChachaPolyIetfTV {
    /// Creates a random test vector
    pub fn random(limit: usize, rng: &mut SecureRng) -> Self {
        Self {
            key: rng.random_vec(32),
            nonce: rng.random_vec(12),
            plaintext: rng.random_len_vec(0..limit),
            ad: rng.random_len_vec(0..limit)
        }
    }
    
    /// Tests the test vector
    pub fn test(self) {
        // Seal the data using `crypto_api_chachapoly`
        let mut ct_ours = vec![0u8; self.plaintext.len() + 16];
        ChachaPolyIetf.seal_to(
            &mut ct_ours, &self