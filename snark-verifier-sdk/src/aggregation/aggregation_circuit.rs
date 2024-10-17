use std::fs::File;

use halo2_base::{
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{self, Circuit, ConstraintSystem, Selector},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    },
    Context, ContextParams,
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::native::NativeLoader,
    pcs::{kzg::KzgAccumulator, AccumulationSchemeProver},
    util::arithmetic::fe_to_limbs,
    verifier::PlonkVerifier,
};

use crate::{
    aggregation::{
        aggregate,
        config::{AggregationConfig, AggregationConfigParams},
        flatten_accumulator, POSEIDON_SPEC,
    },
    types::{Halo2Loader, KzgAs, KzgBDFG, PoseidonTranscript, Shplonk, Svk},
    CircuitExt, Snark, SnarkWitness, BITS, LIMBS,
};

/// Aggregation circuit that does not re-expose any public inputs from aggregated snarks
///
/// This is mostly a reference implementation. In practice one will probably need to re-implement the circuit for one's particular use case with specific instance logic.
#[derive(Clone)]
pub struct AggregationCircuit {
    pub(crate) svk: Svk,
    pub(crate) snarks: Vec<SnarkWitness>,
    // the public instances from previous snarks that were aggregated, now collected as PRIVATE assigned values
    // the user can optionally append these to `inner.assigned_instances` to expose them
    pub(crate) instances: Vec<Fr>,
    // accumulation scheme proof, private input
    pub(crate) as_proof: Value<Vec<u8>>,
}

impl AggregationCircuit {
    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark>,
        rng: impl Rng + Send,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        // TODO: this is all redundant calculation to get the public output
        // Halo2 should just be able to expose public output to instance column directly
        let mut transcript_read =
            PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                transcript_read.new_stream(snark.proof.as_slice());
                let proof = Shplonk::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript_read,
                );
                Shplonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
            })
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript_write = PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                vec![],
                POSEIDON_SPEC.clone(),
            );
            // We always use SHPLONK for accumulation scheme when aggregating proofs
            let accumulator =
                KzgAs::create_proof(&Default::default(), &accumulators, &mut transcript_write, rng)
                    .unwrap();
            (accumulator, transcript_write.finalize())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y].map(fe_to_limbs::<_, _, LIMBS, BITS>).concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_proof: Value::known(as_proof),
        }
    }

    pub fn instance(&self) -> Vec<Fr> {
        self.instances.clone()
    }

    pub fn succinct_verifying_key(&self) -> &Svk {
        &self.svk
    }

    pub fn snarks(&self) -> &[SnarkWitness] {
        &self.snarks
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // [..lhs, ..rhs]
        vec![4 * LIMBS]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instance()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        config.gate().basic_gates[0].iter().map(|gate| gate.q_enable).collect()
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self.snarks.iter().map(SnarkWitness::without_witnesses).collect(),
            instances: Vec::new(),
            as_proof: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = std::env::var("VERIFY_CONFIG")
            .unwrap_or_else(|_| "configs/verify_circuit.config".to_owned());
        let params: AggregationConfigParams = serde_json::from_reader(
            File::open(path.as_str()).unwrap_or_else(|_| panic!("{path:?} does not exist")),
        )
        .unwrap();

        AggregationConfig::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        #[cfg(feature = "display")]
        let witness_time = start_timer!(|| "synthesize | Aggregation Circuit");
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
                    let (_, acc) =
                        aggregate::<KzgBDFG>(&self.svk, &loader, &self.snarks, self.as_proof());

                    instances.extend(
                        flatten_accumulator(acc).iter().map(|assigned| assigned.cell().clone()),
                    );

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
