use super::{TestCircuit1, TestCircuit2};
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
fn test_shplonk_then_sphplonk_with_evm_verification() {
    let path = "./configs/example_evm_accumulator.json";
    let agg_config: AggregationConfigParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let k = 8;
    let k_agg = agg_config.degree;

    let mut rng = test_rng();
    let params_outer = gen_srs(k_agg);
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };

    // =================================
    // inner circuit
    // =================================

    // Proof for circuit 1
    let circuit_1 = TestCircuit1::rand(&mut rng);
    let pk_inner_1 = gen_pk(&params_inner, &circuit_1, Some(Path::new("data/inner_1.pkey")));
    let snarks_1 = gen_snark_shplonk(&params_inner, &pk_inner_1, circuit_1.clone(), None::<String>);
    println!("finished snark generation for circuit 1");

    // Another Proof for circuit 1
    let circuit_2 = TestCircuit1::rand(&mut rng);
    let pk_inner_2 = gen_pk(&params_inner, &circuit_2, Some(Path::new("data/inner_2.pkey")));
    let snarks_2 = gen_snark_shplonk(&params_inner, &pk_inner_2, circuit_1.clone(), None::<String>);
    println!("finished snark generation for circuit 1");

    // Proof for circuit 2
    let circuit_3 = TestCircuit2::rand(&mut rng);
    let pk_inner_3 = gen_pk(&params_inner, &circuit_1, Some(Path::new("data/inner_3.pkey")));
    let snarks_3 = gen_snark_shplonk(&params_inner, &pk_inner_3, circuit_3.clone(), None::<String>);
    println!("finished snark generation for circuit 1");

    // =================================
    // aggregation circuit
    // =================================
    let snarks = vec![snarks_1, snarks_2, snarks_3];
    let agg_circuit = AggregationCircuit::new::<KzgAs<Bn256, Bdfg21>>(
        CircuitBuilderStage::Mock,
        None,
        agg_config.lookup_bits,
        &params_outer,
        snarks.clone(),
    );
    agg_circuit.config(agg_config.degree, None);
    set_var("LOOKUP_BITS", agg_config.lookup_bits.to_string());

    let pk_outer = gen_pk(&params_outer, &agg_circuit, Some(Path::new("data/outer.pkey")));
    println!("finished outer pk generation");

    let deployment_code = gen_evm_verifier::<AggregationCircuit, KzgAs<Bn256, Bdfg21>>(
        &params_outer,
        pk_outer.get_vk(),
        agg_circuit.num_instance(),
        Some(Path::new("data/single_layer_recur.sol")),
    );
    println!("finished bytecode generation");

    let break_points = agg_circuit.break_points();
    drop(agg_circuit);
    let agg_circuit = AggregationCircuit::new::<KzgAs<Bn256, Bdfg21>>(
        CircuitBuilderStage::Prover,
        Some(break_points),
        agg_config.lookup_bits,
        &params_outer,
        snarks,
    );

    let instances = agg_circuit.instances();
    let proof =
        gen_evm_proof_shplonk(&params_outer, &pk_outer, agg_circuit.clone(), instances.clone());
    println!("finished aggregation generation");

    evm_verify(deployment_code, instances, proof)
}
