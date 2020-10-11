
use std::cmp::min;


/// Loads `key` into `r` and `s` and computes the key-based multipliers into `u`
pub fn poly1305_init(r: &mut[u32], s: &mut[u32], u: &mut[u32], key: &[u8]) {
    // Load key
    r[0] = and!(shr!(read32_le!(&key[ 0..]), 0), 0x03FFFFFF);
    r[1] = and!(shr!(read32_le!(&key[ 3..]), 2), 0x03FFFF03);
    r[2] = and!(shr!(read32_le!(&key[ 6..]), 4), 0x03FFC0FF);
    r[3] = and!(shr!(read32_le!(&key[ 9..]), 6), 0x03F03FFF);
    r[4] = and!(shr!(read32_le!(&key[12..]), 8), 0x000FFFFF);
    
    s[0] = read32_le!(&key[16..]);
    s[1] = read32_le!(&key[20..]);
    s[2] = read32_le!(&key[24..]);
    s[3] = read32_le!(&key[28..]);
    
    // Pre-compute multipliers
    u[0] = 0;
    u[1] = mul!(r[1], 5);
    u[2] = mul!(r[2], 5);
    u[3] = mul!(r[3], 5);
    u[4] = mul!(r[4], 5);
}
/// Updates `a` with `data` using the key `r` and the multipliers `u`
///