
/// ChaCha20 constants
const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];


/// Performs the ChaCha20 rounds over `state`
fn chacha20_rounds(state: &mut[u32]) {
    for _ in 0..10 {
        /// A ChaCha20 quarterround
        macro_rules! quarterround {
            ($a:expr, $b:expr, $c:expr, $d:expr) => ({
                state[$a] = add!(state[$a], state[$b]);
                state[$d] = xor!(state[$d], state[$a]);
                state[$d] = or!(shl!(state[$d], 16), shr!(state[$d], 16));
                state[$c] = add!(state[$c], state[$d]);
                state[$b] = xor!(state[$b], state[$c]);
                state[$b] = or!(shl!(state[$b], 12), shr!(state[$b], 20));
                state[$a] = add!(state[$a], state[$b]);
                state[$d] = xor!(state[$d], state[$a]);
                state[$d] = or!(shl!(state[$d],  8), shr!(state[$d], 24));
                state[$c] = add!(state[$c], state[$d]);
                state[$b] = xor!(state[$b], state[$c]);
                state[$b] = or!(shl!(state[$b],  7), shr!(state[$b], 25));
            });
        }
        
        // Perform 8 quarterrounds (2 rounds)
        quarterround!( 0,  4,  8, 12);
        quarterround!( 1,  5,  9, 13);
        quarterround!( 2,  6, 10, 14);
        quarterround!( 3,  7, 11, 15);