//! This module concretize generic types with Bn256 curve and BDFG KZG scheme.

use super::{BITS, LIMBS};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use lazy_static::lazy_static;
use snark_verifier::{
    loader::halo2::{halo2_ecc::ecc::BaseFieldEccChip as EccChip, Halo2Loader as Loader},
    pcs::kzg::{
        Bdfg21, Kzg, KzgAs as KzgAccumulationScheme, KzgSuccinctVerifyingKey, LimbsEncoding,
    },
    verifier, PoseidonSpec,
};

use crate::param::{RATE, R_F, R_P, T};

lazy_static! {
    pub static ref POSEIDON_SPEC: PoseidonSpec<Fr, T, RATE> = PoseidonSpec::new(R_F, R_P);
}

/// Transcript instantiated with Poseidon
pub type PoseidonTranscript<L, S> =
    snark_verifier::system::halo2::transcript::halo2::PoseidonTranscript<
        G1Affine,
        L,
        S,
        T,
        RATE,
        R_F,
        R_P,
    >;

/// Plonk configured with PCS.
/// PCS is either `Kzg<Bn256, Gwc19>` or `Kzg<Bn256, Bdfg21>`
pub type Plonk<PCS> = verifier::Plonk<PCS, LimbsEncoding<LIMBS, BITS>>;

/// KZG instantiated with BDFG21
pub type KzgBDFG = Kzg<Bn256, Bdfg21>;

/// Accumulator scheme build from KZG over BDFG21 scheme
pub type KzgAs = KzgAccumulationScheme<KzgBDFG>;

/// SHPlonk
pub type Shplonk = Plonk<KzgBDFG>;

/// KZG succinct verifying key.
pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;

/// Non-native arithmetic chip
pub type BaseFieldEccChip = EccChip<G1Affine>;

/// Halo2 loader
pub type Halo2Loader<'a> = Loader<'a, G1Affine, BaseFieldEccChip>;
