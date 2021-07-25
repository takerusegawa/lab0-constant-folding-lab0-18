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
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>
}
impl CryptoTestVector {
    /// Loads the test vectors
    pub fn load() -> Vec<Self> {
        let json = json::parse(TEST_VECTORS).unwrap();
        let mut vecs = Vec::new();
        for vec in json["crypto"].checked_array_iter() {
            vecs.push(Self {
                name: vec["name"].checked_string(),
                key: vec["key"].checked_bytes(),
                nonce: vec["nonce"].checked_bytes(),
                plaintext: vec["plaintext"].checked_bytes(),
                ciphertext: vec["ciphertext"].checked_bytes(),
            });
        }
        vecs
    }
    
    /// Tests the encryption
    pub fn test_encryption(&self) -> &Self {
        // Encrypt in place
        let mut buf = self.plaintext.clone();
        ChaCha20Ietf::cipher()
            .encrypt(&mut buf, self.plaintext.len(), &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.ciphertext, "Test vector: \"{}\"", self.name);
        
        // Encrypt to buffer
        let mut buf = vec![0; self.ciphertext.len()];
        ChaCha20Ietf::cipher()
            .encrypt_to(&mut buf, &self.plaintext, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.ciphertext, "Test vector: \"{}\"", self.name);
        
        self
    }
    
    /// Tests the decryption
    pub fn test_decryption(&self) -> &Self {
        // Decrypt in place
        let mut buf = self.ciphertext.clone();
        ChaCha20Ietf::cipher()
            .decrypt(&mut buf, self.ciphertext.len(), &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.plaintext, "Test vector: \"{}\"", self.name);
        
        // Decrypt to buffer
        let mut buf = vec![