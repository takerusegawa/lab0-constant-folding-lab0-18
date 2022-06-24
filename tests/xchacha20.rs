mod shared;

use shared::{ JsonValueExt, ResultExt };
use crypto_api_chachapoly::XChaCha20;
use json::JsonValue;


/// The test vectors
const TEST_VECTORS: &str = include_str!("xchacha20.json");


/// A crypto test vector
#[derive(Debug)]
struct CryptoTestVector {
    name: String,
    key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>
}
impl CryptoTestVector {
    /// Loads the test vectors
    pub fn load() -> Vec<Self> {
        let json = json::parse(TEST_VECTORS).unwrap();
        let mut vecs = Vec::new();
        for vec in json["crypto"].checked_array_iter() {
            v