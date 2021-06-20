mod shared;

use shared::{ JsonValueExt, ResultExt };
use crypto_api_chachapoly::ChaCha20Ietf;
use json::JsonValue;


/// The test vectors
const TEST_VECTORS: &str = include_str!("chacha20_ietf.json");


/// A crypto test vector
#[derive(Debug)]
struct CryptoTestVector {
    name: String,
    key: Vec<u8>,
    