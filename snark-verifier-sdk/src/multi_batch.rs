//! APIs to handle multi-batching snarks.
//!
//! In each batch iteration, we are doing two layers of recursions.
//! - use a wide recursive circuit to aggregate the proofs
//! - use a slim recursive circuit to shrink the size of the aggregated proof
//!

mod evm;
mod halo2;
mod hash;

#[cfg(test)]
mod tests;

pub use evm::*;
pub use halo2::*;
pub(crate) use hash::*;
