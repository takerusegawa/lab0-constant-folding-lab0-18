#![forbid(unsafe_code)]

#[macro_use] pub mod core;
#[macro_use] mod verify_input;
mod chacha20_ietf;
mod xchacha20;
mod poly1305;
mod chachapoly_ietf;
mod xchachapoly;

pub use crate::{
    chacha20_ietf::ChaCha20Ie