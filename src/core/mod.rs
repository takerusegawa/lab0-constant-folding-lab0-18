
/// Addition without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! add {
    ($a:expr, $b:expr) => ({ $a.wrapping_add($b) });
    ($a:expr, $b:expr, $c:expr) => ({ $a.wrapping_add($b).wrapping_add($c) });
    ($a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => ({
        $a.wrapping_add($b).wrapping_add($c).wrapping_add($d).wrapping_add($e)
    });
}

/// Subtraction without underflow-trap
#[doc(hidden)] #[macro_export] macro_rules! sub {
    ($a:expr, $b:expr) => ({ $a.wrapping_sub($b) });
}
/// Multiplies without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! mul {
    ($a:expr, $b:expr) => ({ $a.wrapping_mul($b) });
}

/// Right-shift without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! shr {
    ($a:expr, $b:expr) => ({ $a.wrapping_shr($b) });
}
/// Left-shift without overflow-trap
#[doc(hidden)] #[macro_export] macro_rules! shl {
    ($a:expr, $b:expr) => ({ $a.wrapping_shl($b) });
}

/// Negates without trap
#[doc(hidden)] #[macro_export] macro_rules! neg {
    ($a:expr) => ({ $a.wrapping_neg() });
}

/// Perform an AND
#[doc(hidden)] #[macro_export] macro_rules! and {
    ($a:expr, $b:expr) => ({ $a & $b });
}
/// Perform an OR
#[doc(hidden)] #[macro_export] macro_rules! or {
    ($a:expr, $b:expr) => ({ $a | $b });
    ($a:expr, $b:expr, $c:expr, $d:expr) => ({ $a | $b | $c | $d });
}
/// Perform a XOR
#[doc(hidden)] #[macro_export] macro_rules! xor {
    ($a:expr, $b:expr) => ({ $a ^ $b });
}

/// Checks if `$a > $b` and returns a `u32` (where `1` is `true` and `0` is `false`)
#[doc(hidden)] #[macro_export] macro_rules! gt {
    ($a:expr, $b:expr) => ({
        let c = sub!($b, $a);
        shr!(xor!(c, and!(xor!($a, $b), xor!($a, c))), 31)