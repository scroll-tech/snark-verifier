use super::{TestCircuit1, TestCircuit2};
use crate::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    gen_pk,
    halo2::{
        aggregation::{AggregationCircuit, AggregationConfigParams, VerifierUniversality},
        gen_snark_shplonk,
    },
    CircuitExt, SHPLONK,
};
use ark_std::test_rng;
use halo2_base::{gates::circuit::CircuitBuilderStage, halo2_proofs};
use halo2_proofs::{halo2curves::bn256::Bn256, poly::commitment::Params};
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs,
    pcs::kzg::{Bdfg21, KzgAs},
};
use std::path::Path;

#[test]
fn test_shplonk_then_sphplonk_with_evm_verification() {
    std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");
    let k = 8;
    let k_agg = 21;

    let mut rng = test_rng();
    let params_outer = gen_srs(k_agg);
    let params_inner = {
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
    println!("finished snark generation for circuit 1");

    // Another Proof for circuit 1
    let circuit_2 = TestCircuit1::rand(&mut rng);
    let pk_inner_2 = gen_pk(&params_inner, &circuit_2, Some(Path::new("data/inner_2.pkey")));
    let snarks_2 = gen_snark_shplonk(
        &params_inner,
        &pk_inner_2,
        circuit_1.clone(),
        &mut rng,
        Some(Path::new("data/inner_2.snark")),
    );
    println!("finished snark generation for circuit 1");

    // Proof for circuit 2
    let circuit_3 = TestCircuit2::rand(&mut rng);
    let pk_inner_3 = gen_pk(&params_inner, &circuit_1, Some(Path::new("data/inner_3.pkey")));
    let snarks_3 = gen_snark_shplonk(
        &params_inner,
        &pk_inner_3,
        circuit_3.clone(),
        &mut rng,
        Some(Path::new("data/inner_3.snark")),
    );
    println!("finished snark generation for circuit 1");

    // aggregation circuit
    let snarks = vec![snarks_1, snarks_2, snarks_3];
    // let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);

    let mut agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams { degree: k_agg, lookup_bits: 18, ..Default::default() },
        &params_outer,
        snarks.clone(),
        VerifierUniversality::PreprocessedAsWitness,
    );
    let agg_config = agg_circuit.calculate_params(Some(10));

    let pk_outer = gen_pk(&params_outer, &agg_circuit, Some(Path::new("data/outer.pkey")));
    let break_points = agg_circuit.break_points();

    println!("finished outer pk generation");
    let instances = agg_circuit.instances();

    let agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        agg_config,
        &params_outer,
        snarks,
        VerifierUniversality::PreprocessedAsWitness,
    )
    .use_break_points(break_points.clone());

    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances.clone(),
        &mut rng,
    );
    println!("finished aggregation generation");

    let deployment_code = gen_evm_verifier::<AggregationCircuit, KzgAs<Bn256, Bdfg21>>(
        &params_outer,
        pk_outer.get_vk(),
        agg_circuit.num_instance(),
        Some(Path::new("data/single_layer_recur.sol")),
    );

    println!("finished bytecode generation");
    evm_verify(deployment_code, instances, proof)
}
