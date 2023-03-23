//! Place holders for CircuitExt Implementation of EVM circuits
//!
//! TODO: move those definitions to zkevm-circuit repo.

mod evm_circuit;
mod mpt_circuit;
mod poseidon_circuit;
mod state_circuit;
mod super_circuit;

#[cfg(test)]
mod test {
    use ark_std::test_rng;
    use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::fs::gen_srs};

    use crate::{
        gen_pk,
        halo2::{gen_snark_shplonk, verify_snark_shplonk},
        CircuitExt,
    };

    // A simple unit test to check that C has implemented CircuitExt correctly.
    pub(crate) fn test_circuit_native_verification<C: CircuitExt<Fr>>(circuit: C) -> bool {
        std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");

        let mut rng = test_rng();
        let params = gen_srs(10);

        let pk = gen_pk(&params, &circuit, None);
        let vk = pk.get_vk();

        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        verify_snark_shplonk::<C>(&params, snark, vk)
    }
}
