use super::TestCircuit1;
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
fn test_two_layer_aggregation_evm_verification() {
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

    // layer 1 snarks
    let circuit = TestCircuit1::rand(&mut rng);
    let pk_inner = gen_pk(&params_inner, &circuit, None);
    let snarks = (0..3)
        .map(|i| {
            gen_snark_shplonk(
                &params_inner,
                &pk_inner,
                circuit.clone(),
                &mut rng,
                Some(Path::new(&format!("data/inner_{}.snark", i).to_string())),
            )
        })
        .collect::<Vec<_>>();
    println!("finished snark generation");

    // layer 2, first aggregation
    let first_agg_proof = {
        let mut first_agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Keygen,
            AggregationConfigParams { degree: k_agg, lookup_bits: 18, ..Default::default() },
            &params_outer,
            snarks.clone(),
            VerifierUniversality::PreprocessedAsWitness,
        );
        let first_agg_config = first_agg_circuit.calculate_params(Some(10));

        let pk_outer = gen_pk(&params_outer, &first_agg_circuit, None);
        let break_points = first_agg_circuit.break_points();

        println!("finished outer pk generation");

        let first_agg_circuit = AggregationCircuit::new::<SHPLONK>(
            CircuitBuilderStage::Prover,
            first_agg_config,
            &params_outer,
            snarks,
            VerifierUniversality::PreprocessedAsWitness,
        )
        .use_break_points(break_points.clone());

        let first_agg_proof = gen_snark_shplonk(
            &params_outer,
            &pk_outer,
            first_agg_circuit.clone(),
            &mut rng,
            Some(Path::new("data/outer.snark")),
        );
        println!("finished outer proof generation");
        first_agg_proof
    };

    // layer 3, second aggregation
    let mut second_agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Keygen,
        AggregationConfigParams { degree: k_agg, lookup_bits: 18, ..Default::default() },
        &params_outer,
        [first_agg_proof.clone()],
        VerifierUniversality::PreprocessedAsWitness,
    );
    let second_agg_config = second_agg_circuit.calculate_params(Some(10));

    let pk_agg = gen_pk(&params_outer, &second_agg_circuit, None);
    let break_points = second_agg_circuit.break_points();

    let second_agg_circuit = AggregationCircuit::new::<SHPLONK>(
        CircuitBuilderStage::Prover,
        second_agg_config,
        &params_outer,
        [first_agg_proof],
        VerifierUniversality::PreprocessedAsWitness,
    )
    .use_break_points(break_points.clone());

    let deployment_code = gen_evm_verifier::<AggregationCircuit, KzgAs<Bn256, Bdfg21>>(
        &params_outer,
        pk_agg.get_vk(),
        second_agg_circuit.num_instance(),
        Some(Path::new("data/two_layer_recur.sol")),
    );
    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_agg,
        second_agg_circuit.clone(),
        second_agg_circuit.instances().clone(),
        &mut rng,
    );
    println!("finished bytecode generation");
    evm_verify(deployment_code, second_agg_circuit.instances(), proof)
}
