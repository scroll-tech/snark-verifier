use super::{TestCircuit1, TestCircuit2};
use crate::{
    aggregation::aggregation_circuit::AggregationCircuit,
    evm_api::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    halo2_api::{gen_pk, gen_snark_shplonk},
    CircuitExt,
};
use ark_std::test_rng;
use halo2_base::halo2_proofs;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::commitment::Params};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs,
    pcs::kzg::{Bdfg21, Kzg},
};
use std::path::Path;

#[test]
fn test_shplonk_then_sphplonk_with_evm_verification() {
    std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");
    let k = 8;
    let k_agg = 24;

    let mut rng = test_rng();
    let params_inner = {
        let params_outer = gen_srs(k_agg);
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };

    // Proof for circuit 1
    let circuit_1 = TestCircuit1::rand(&mut rng);
    let pk_inner_1 = gen_pk(&params_inner, &circuit_1, Some(Path::new("data/inner_1.pkey")));
    let snarks_1 = gen_snark_shplonk(
        &params_inner,
        &pk_inner_1,
        circuit_1.clone(),
        &mut rng,
        Some(Path::new("data/inner_1.snark")),
    );
    let instances = circuit_1.instances();
    let proof = gen_evm_proof_shplonk(
        &params_inner,
        &pk_inner_1,
        circuit_1.clone(),
        instances.clone(),
        &mut rng,
    );
    println!("finished aggregation generation");

    let deployment_code = gen_evm_verifier::<TestCircuit1, Kzg<Bn256, Bdfg21>>(
        &params_inner,
        pk_inner_1.get_vk(),
        circuit_1.num_instance(),
        Some(Path::new("data/single_layer_recur.sol")),
    );

    println!("finished bytecode generation");
    evm_verify(deployment_code, instances, proof)
}
