#![allow(clippy::clone_on_copy)]
use crate::{
    aggregation::{aggregate, flatten_accumulator},
    types::Halo2Loader,
    CircuitExt, Snark, LIMBS,
};
#[cfg(feature = "display")]
use ark_std::end_timer;
#[cfg(feature = "display")]
use ark_std::start_timer;
use halo2_base::utils::value_to_option;
use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{self, Circuit, Selector},
        poly::kzg::commitment::ParamsKZG,
    },
    Context, ContextParams,
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};

use super::{aggregation_circuit::AggregationCircuit, config::AggregationConfig};

/// This circuit takes multiple SNARKs and passes through all of their instances except the old accumulators.
///
/// * If `has_prev_accumulator = true`, we assume all SNARKs are of aggregation circuits with old accumulators
/// only in the first instance column.
/// * Otherwise if `has_prev_accumulator = false`, then all previous instances are passed through.
#[derive(Clone)]
pub struct PublicAggregationCircuit {
    pub aggregation: AggregationCircuit,
    pub has_prev_accumulator: bool,
}

impl PublicAggregationCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: Vec<Snark>,
        has_prev_accumulator: bool,
        rng: &mut (impl Rng + Send),
    ) -> Self {
        Self { aggregation: AggregationCircuit::new(params, snarks, rng), has_prev_accumulator }
    }
}

impl CircuitExt<Fr> for PublicAggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        let prev_num = self
            .aggregation
            .snarks
            .iter()
            .map(|snark| snark.instances.iter().map(|instance| instance.len()).sum::<usize>())
            .sum::<usize>()
            - self.aggregation.snarks.len() * 4 * LIMBS * usize::from(self.has_prev_accumulator);
        vec![4 * LIMBS + prev_num]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        let start_idx = 4 * LIMBS * usize::from(self.has_prev_accumulator);
        let instance = self
            .aggregation
            .instances
            .iter()
            .cloned()
            .chain(self.aggregation.snarks.iter().flat_map(|snark| {
                snark.instances.iter().enumerate().flat_map(|(i, instance)| {
                    instance[usize::from(i == 0) * start_idx..]
                        .iter()
                        .map(|v| value_to_option(*v).unwrap())
                })
            }))
            .collect_vec();
        vec![instance]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        AggregationCircuit::selectors(config)
    }
}

impl Circuit<Fr> for PublicAggregationCircuit {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            aggregation: self.aggregation.without_witnesses(),
            has_prev_accumulator: self.has_prev_accumulator,
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        AggregationCircuit::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        #[cfg(feature = "display")]
        let witness_time = start_timer!(|| { "synthesize | EVM verifier" });
        config.range().load_lookup_table(&mut layouter).expect("load range lookup table");
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut instances = vec![];
        layouter
            .assign_region(
                || "",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let ctx = Context::new(
                        region,
                        ContextParams {
                            max_rows: config.gate().max_rows,
                            num_context_ids: 1,
                            fixed_columns: config.gate().constants.clone(),
                        },
                    );

                    let ecc_chip = config.ecc_chip();
                    let loader = Halo2Loader::new(ecc_chip, ctx);
                    let (prev_instances, acc) = aggregate::<Kzg<Bn256, Bdfg21>>(
                        &self.aggregation.svk,
                        &loader,
                        &self.aggregation.snarks,
                        self.aggregation.as_proof(),
                    );

                    // accumulator
                    instances.extend(flatten_accumulator(acc).iter().map(|a| a.cell().clone()));
                    // prev instances except accumulators
                    let start_idx = 4 * LIMBS * usize::from(self.has_prev_accumulator);
                    for prev_instance in prev_instances {
                        instances
                            .extend(prev_instance[start_idx..].iter().map(|a| a.cell().clone()));
                    }

                    config.range().finalize(&mut loader.ctx_mut());
                    #[cfg(feature = "display")]
                    loader.ctx_mut().print_stats(&["Range"]);
                    Ok(())
                },
            )
            .unwrap();
        // Expose instances
        for (i, cell) in instances.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.instance, i)?;
        }
        #[cfg(feature = "display")]
        end_timer!(witness_time);
        Ok(())
    }
}
