use crate::core::poly1305::{ poly1305_init, poly1305_update, poly1305_finish };
use crypto_api::{
    mac::{ MacInfo, Mac },
    rng::{ SecureRng, SecKeyGen }
};
use std::error::Error;


/// The size of a Poly1305 k