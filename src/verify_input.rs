
/// A `usize` extension to use `usize`s as constrainable values
pub trait UsizeExt {
    /// Get the constrainable value
    fn _cv(&self) -> usize;
}
impl UsizeExt for usize {
    fn _cv(&self) -> usize {
        *self
    }
}
/// A slice extension to use slice as constrainable values
pub trait SliceExt {
    /// Get the constrainable value
    fn _cv(&self) -> usize;
}
impl<T: AsRef<[u8]>> SliceExt for T {
    fn _cv(&self) -> usize {
        self.as_ref().len()
    }
}


/// Verifies that
///  - `$buf` is can hold *exactly* `$size` bytes
macro_rules! vfy_keygen {
    ($size:expr => $buf:expr) => ({
        #[allow(unused_imports)]
        use $crate::verify_input::{ UsizeExt, SliceExt };
        
        let error = match true {
            _ if $buf._cv() != $size => Err("Invalid buffer size"),
            _ => Ok(())
        };
        error.map_err(|e| $crate::ChachaPolyError::ApiMisuse(e))?;
    });
}


/// Verifies the encryption parameters