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
    key: