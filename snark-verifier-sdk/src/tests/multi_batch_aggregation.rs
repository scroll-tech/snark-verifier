use super::TestCircuit1;
use crate::multi_batch::{gen_four_layer_recursive_snark, gen_two_layer_recursive_snark};
use crate::Snark;
use crate::{gen_pk, halo2::gen_snark_shplonk};
use ark_std::test_rng;
use halo2_base::halo2_proofs;
use halo2_proofs::poly::commitment::Params;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;

#[test]
fn test_partial_multi_batch_aggregation() {
    let k = 8;

    // let config = MultiBatchConfig::new(k, k_layer_1, k_layer_2);
    println!("finished configurations");
    let mut rng = test_rng();
    let params = gen_srs(26 as u32);
    let mut param_inner = params.clone();
    param_inner.downsize(k as u32);
    println!("finished SRS generation");

    let circuits: Vec<_> = (0..2).map(|_| TestCircuit1::rand(&mut rng)).collect();
    let pk = gen_pk(&param_inner, &circuits[0], None);
    println!("finished pk and circuits generation");

    // ===============================================
    // convert input circuits to snarks
    // ===============================================
    let input_snarks: Vec<Snark> = {
        let k = pk.get_vk().get_domain().k();
        println!("inner circuit k = {}", k);
        circuits
            .iter()
            .map(|circuit| {
                gen_snark_shplonk::<TestCircuit1>(
                    &param_inner,
                    &pk,
                    circuit.clone(),
                    &mut rng,
                    None::<String>,
                )
            })
            .collect()
    };
    println!("Finished input snark generation");

    let _snark = gen_two_layer_recursive_snark(&params, input_snarks, &mut rng);
}

#[test]
fn test_full_multi_batch_aggregation() {
    let k = 8;

    // let config = MultiBatchConfig::new(k, k_layer_1, k_layer_2);
    println!("finished configurations");
    let mut rng = test_rng();
    let params = gen_srs(26 as u32);
    let mut param_inner = params.clone();
    param_inner.downsize(k as u32);
    println!("finished SRS generation");

    let circuit_vecs: Vec<Vec<_>> =
        (0..2).map(|_| (0..2).map(|_| TestCircuit1::rand(&mut rng)).collect()).collect();
    let pk = gen_pk(&param_inner, &circuit_vecs[0][0], None);
    println!("finished pk and circuits generation");

    // ===============================================
    // convert input circuits to snarks
    // ===============================================
    let input_snarks: Vec<Vec<Snark>> = {
        let k = pk.get_vk().get_domain().k();
        println!("inner circuit k = {}", k);
        circuit_vecs
            .iter()
            .map(|circuits| {
                circuits
                    .iter()
                    .map(|circuit| {
                        gen_snark_shplonk::<TestCircuit1>(
                            &param_inner,
                            &pk,
                            circuit.clone(),
                            &mut rng,
                            None::<String>,
                        )
                    })
                    .collect()
            })
            .collect()
    };
    println!("Finished input snark generation");

    let _snark = gen_four_layer_recursive_snark(&params, input_snarks, &mut rng);
}
