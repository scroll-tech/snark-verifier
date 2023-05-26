use super::TestCircuit1;
use crate::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier};
use crate::halo2::aggregation::{AggregationCircuit, AggregationConfigParams};
use crate::CircuitExt;
use crate::{gen_pk, halo2::gen_snark_shplonk};
use ark_std::test_rng;
use halo2_base::gates::builder::CircuitBuilderStage;
use halo2_base::halo2_proofs;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::poly::commitment::Params;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier::pcs::kzg::{Bdfg21, KzgAs};
use std::env::set_var;
use std::fs::File;
use std::path::Path;

#[test]
fn test_two_layer_aggregation_evm_verification() {
    let k = 8;
    let path = "./configs/two_layer_recursion_first_layer.json";
    let layer_1_agg_config: AggregationConfigParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let path = "./configs/two_layer_recursion_second_layer.json";
    let layer_2_agg_config: AggregationConfigParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let mut rng = test_rng();
    let params_outer = gen_srs(layer_2_agg_config.degree);
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };
    // =================================
    // inner circuit
    // =================================
    // layer 1 snarks
    let circuit = TestCircuit1::rand(&mut rng);
    let pk_inner = gen_pk(&params_inner, &circuit, None);
    let snarks = (0..3)
        .map(|_| gen_snark_shplonk(&params_inner, &pk_inner, circuit.clone(), None::<String>))
        .collect::<Vec<_>>();
    println!("finished snark generation");
    // =================================
    // layer 2 circuit
    // =================================
    // layer 2, first aggregation
    let first_agg_circuit = AggregationCircuit::new::<KzgAs<Bn256, Bdfg21>>(
        CircuitBuilderStage::Mock,
        None,
        layer_1_agg_config.lookup_bits,
        &params_outer,
        snarks.clone(),
    );
    first_agg_circuit.config(layer_1_agg_config.degree, None);
    set_var("LOOKUP_BITS", layer_1_agg_config.lookup_bits.to_string());

    let pk_outer = gen_pk(&params_outer, &first_agg_circuit, None);
    println!("finished outer pk generation");
    let break_points = first_agg_circuit.break_points();
    drop(first_agg_circuit);
    let first_agg_circuit = AggregationCircuit::new::<KzgAs<Bn256, Bdfg21>>(
        CircuitBuilderStage::Prover,
        Some(break_points),
        layer_1_agg_config.lookup_bits,
        &params_outer,
        snarks,
    );

    let first_agg_proof =
        gen_snark_shplonk(&params_outer, &pk_outer, first_agg_circuit, None::<String>);
    println!("finished outer proof generation");
    // =================================
    // layer 3 circuit
    // =================================
    // layer 3, second aggregation
    let second_agg_circuit = AggregationCircuit::new::<KzgAs<Bn256, Bdfg21>>(
        CircuitBuilderStage::Mock,
        None,
        layer_2_agg_config.lookup_bits,
        &params_outer,
        [first_agg_proof.clone()],
    );
    second_agg_circuit.config(layer_2_agg_config.degree, None);
    set_var("LOOKUP_BITS", layer_2_agg_config.lookup_bits.to_string());

    let pk_agg = gen_pk(&params_outer, &second_agg_circuit, None);

    let deployment_code = gen_evm_verifier::<AggregationCircuit, KzgAs<Bn256, Bdfg21>>(
        &params_outer,
        pk_agg.get_vk(),
        second_agg_circuit.num_instance(),
        Some(Path::new("data/two_layer_recur.sol")),
    );

    let break_points = second_agg_circuit.break_points();
    drop(second_agg_circuit);
    let second_agg_circuit = AggregationCircuit::new::<KzgAs<Bn256, Bdfg21>>(
        CircuitBuilderStage::Prover,
        Some(break_points),
        layer_2_agg_config.lookup_bits,
        &params_outer,
        [first_agg_proof],
    );

    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_agg,
        second_agg_circuit.clone(),
        second_agg_circuit.instances().clone(),
    );
    println!("finished bytecode generation");
    evm_verify(deployment_code, second_agg_circuit.instances(), proof)
}
