#![feature(associated_type_defaults)]
#[cfg(feature = "display")]
use ark_std::end_timer;
#[cfg(feature = "display")]
use ark_std::start_timer;
use halo2_base::halo2_proofs;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
pub use snark_verifier::loader::native::NativeLoader;
use std::{
    fs::{
        File, {self},
    },
    io::BufWriter,
    path::Path,
};

#[cfg(feature = "loader_evm")]
pub mod evm;
#[cfg(feature = "loader_halo2")]
pub mod halo2_api;

#[cfg(test)]
mod tests;

mod aggregation;
pub mod circuit_ext;
mod io;
mod param;
mod snark;
pub mod types;

pub use circuit_ext::CircuitExt;
pub use io::{read_instances, write_instances};
pub use param::{BITS, LIMBS};
pub use snark::{Snark, SnarkWitness};

use crate::io::read_pk;
