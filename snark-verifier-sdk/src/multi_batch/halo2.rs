use crate::gen_pk;
use crate::halo2::aggregation::AggregationCircuit;
use crate::halo2::gen_snark_shplonk;
use crate::Snark;
#[cfg(feature = "display")]
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use rand::Rng;

/// Inputs:
/// - kzg parameters
/// - a list of input snarks
/// - rng
/// 
/// Outputs:
// -
// - a SNARK which is a snark **proof** of statement s, where
//   - s: I have seen the proofs for all circuits c1,...ck
pub fn gen_two_layer_recursive_snark<'params>(
    params: &'params ParamsKZG<Bn256>,
    input_snarks: Vec<Snark>,
    rng: &mut (impl Rng + Send),
) -> Snark {
    let timer = start_timer!(|| "begin two layer recursions");
    // ===============================================
    // first layer
    // ===============================================
    // use a wide config to aggregate snarks

    std::env::set_var("VERIFY_CONFIG", "./configs/two_layer_recursion_first_layer.config");

    let layer_1_snark = {
        let layer_1_circuit = AggregationCircuit::new(&params, input_snarks, rng);
        let layer_1_pk = gen_pk(&params, &layer_1_circuit, None);
        gen_snark_shplonk(&params, &layer_1_pk, layer_1_circuit.clone(), rng, None::<String>)
    };

    log::trace!("Finished layer 1 snark generation");
    // ===============================================
    // second layer
    // ===============================================
    // use a skim config to aggregate snarks

    std::env::set_var("VERIFY_CONFIG", "./configs/two_layer_recursion_second_layer.config");

    let layer_2_circuit = AggregationCircuit::new(&params, [layer_1_snark], rng);
    let layer_2_pk = gen_pk(&params, &layer_2_circuit, None);

    let snark =
        gen_snark_shplonk(&params, &layer_2_pk, layer_2_circuit.clone(), rng, None::<String>);

    log::trace!("Finished layer 2 snark generation");
    end_timer!(timer);
    snark
}

pub fn gen_four_layer_recursive_snark<'params>(
    params: &'params ParamsKZG<Bn256>,
    input_snark_vecs: Vec<Vec<Snark>>,
    rng: &mut (impl Rng + Send),
) -> Snark {
    let timer = start_timer!(|| "begin two layer recursions");

    let mut snarks = vec![];
    let len = input_snark_vecs[0].len();
    let inner_timer = start_timer!(|| "inner layers");
    for input_snarks in input_snark_vecs.iter() {
        assert_eq!(len, input_snarks.len());

        let snark = gen_two_layer_recursive_snark(params, input_snarks.clone(), rng);
        snarks.push(snark);
    }
    end_timer!(inner_timer);

    let outer_timer = start_timer!(|| "outer layers");
    let snark = gen_two_layer_recursive_snark(params, snarks, rng);
    end_timer!(outer_timer);

    end_timer!(timer);
    snark
}
