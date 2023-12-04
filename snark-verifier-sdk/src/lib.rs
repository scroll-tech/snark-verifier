#![feature(lazy_cell)]

#[cfg(feature = "loader_evm")]
mod evm_api;
#[cfg(feature = "loader_halo2")]
mod halo2_api;

#[cfg(test)]
mod tests;

mod aggregation;
mod circuit_ext;
mod file_io;
mod param;
mod snark;
pub mod types;

pub use aggregation::aggregation_circuit::AggregationCircuit;
pub use aggregation::load_verify_circuit_degree;
pub use aggregation::multi_aggregation_circuit::PublicAggregationCircuit;
pub use aggregation::{aggregate, flatten_accumulator};
pub use circuit_ext::CircuitExt;
pub use param::{BITS, LIMBS};
pub use snark::gen_dummy_snark;
pub use snark::{Snark, SnarkWitness};

pub use file_io::{
    // read instances from disk
    read_instances,
    // read pk from disk
    read_pk,
    // read snark from disk
    read_snark,
    // write call date to disk
    write_calldata,
    // write instances to disk
    write_instances,
};

#[cfg(feature = "loader_evm")]
pub use evm_api::{
    // encode instances and proofs as calldata
    encode_calldata,
    // verify instances and proofs with the bytecode
    evm_verify,
    // generate evm proof with keccak that can be verified by bytecode
    gen_evm_proof,
    // generate snark proof with keccak and KZG-GWC that can be verified by bytecode
    gen_evm_proof_gwc,
    // generate evm proof with keccak and KZG-BDFG that can be verified by bytecode
    gen_evm_proof_shplonk,
    // generate the bytecode that verifies proofs
    gen_evm_verifier,
    // generate the bytecode that verifies proofs with keccak and KZG-GWC
    gen_evm_verifier_gwc,
    // generate the bytecode that verifies proofs with keccak and KZG-BDFG
    gen_evm_verifier_shplonk,
    // verify calldata with the bytecode (returns bool)
    verify_evm_calldata,
    // verify instances and proofs with the bytecode (returns bool)
    verify_evm_proof,
};
#[cfg(feature = "loader_halo2")]
pub use halo2_api::{
    // generate pk
    gen_pk,
    // generate proof with poseidon
    gen_proof,
    // generate proof with poseidon and KZG-GWC
    gen_proof_gwc,
    // generate proof with poseidon and KZG-BDFG
    gen_proof_shplonk,
    // generate a snark struct (proof + witnesses for aggregation circuit)
    gen_snark,
    // generate a snark struct (proof + witnesses for aggregation circuit) with KZG-GWC
    gen_snark_gwc,
    // generate a snark struct (proof + witnesses for aggregation circuit) with KZG-BDFG
    gen_snark_shplonk,
    // verify snark
    verify_snark,
    // verify snark KZG-GWC
    verify_snark_gwc,
    // verify snark KZG-BDFG
    verify_snark_shplonk,
};
