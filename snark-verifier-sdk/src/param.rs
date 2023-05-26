/// Number of limbs for non-native field decomposition
pub const LIMBS: usize = 3;
/// Number of bits for each limb.
pub const BITS: usize = 88;

// Poseidon parameters
pub(crate) const T: usize = 5;
pub(crate) const RATE: usize = 4;
pub(crate) const R_F: usize = 8;
pub(crate) const R_P: usize = 60;
