
mod shared;

use shared::{ JsonValueExt, ResultExt };
use crypto_api_chachapoly::ChachaPolyIetf;
use json::JsonValue;


/// The test vectors
const TEST_VECTORS: &str = include_str!("chachapoly_ietf.json");


/// A crypto test vector
#[derive(Debug)]
struct CryptoTestVector {
    name: String,
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
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
                ad: vec["ad"].checked_bytes(),
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
        buf.extend_from_slice(&[0; 16]);
        ChachaPolyIetf::aead_cipher()
            .seal(&mut buf, self.plaintext.len(), &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.ciphertext, "Test vector: \"{}\"", self.name);
        
        // Encrypt to buffer
        let mut buf = vec![0; self.ciphertext.len()];
        ChachaPolyIetf::aead_cipher()
            .seal_to(&mut buf, &self.plaintext, &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.ciphertext, "Test vector: \"{}\"", self.name);
        
        self
    }
    
    /// Tests the decryption
    pub fn test_decryption(&self) -> &Self {
        // Decrypt in place
        let mut buf = self.ciphertext.clone();
        let len = ChachaPolyIetf::aead_cipher()
            .open(&mut buf, self.ciphertext.len(), &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(&buf[..len], self.plaintext.as_slice(), "Test vector: \"{}\"", self.name);
        
        // Decrypt to buffer
        let mut buf = vec![0; self.plaintext.len()];
        ChachaPolyIetf::aead_cipher()
            .open_to(&mut buf, &self.ciphertext, &self.ad, &self.key, &self.nonce)
            .unwrap();
        assert_eq!(buf, self.plaintext, "Test vector: \"{}\"", self.name);
        
        self
    }
}
#[test]
fn test_crypto() {
    for vec in CryptoTestVector::load() {
        vec.test_encryption().test_decryption();
    }
}

