use super::PlonkSuccinctVerifier;
use crate::{BITS, LIMBS};
use halo2_base::{
    gates::{
        builder::{
            assign_threads_in, CircuitBuilderStage, FlexGateConfigParams, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
        },
        range::RangeConfig,
        RangeChip,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{self, Circuit, Column, ConstraintSystem, Instance, Selector},
        poly::{
            commitment::{Params, ParamsProver},
            kzg::commitment::ParamsKZG,
        },
    },
    utils::ScalarField,
    AssignedValue, SKIP_FIRST_PASS,
};
use itertools::Itertools;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use snark_verifier::{
    loader::{
        self,
        halo2::halo2_ecc::{self, bn254::FpChip},
        native::NativeLoader,
    },
    pcs::{
        kzg::{KzgAccumulator, KzgAsProvingKey, KzgAsVerifyingKey, KzgSuccinctVerifyingKey},
        AccumulationScheme, AccumulationSchemeProver, PolynomialCommitmentScheme,
    },
    util::arithmetic::fe_to_limbs,
    verifier::SnarkVerifier,
};
use std::{
    collections::HashMap,
    env::{set_var, var},
    fs::File,
    path::Path,
    rc::Rc,
};

use super::{CircuitExt, PoseidonTranscript, Snark, POSEIDON_SPEC};

pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;
pub type BaseFieldEccChip<'chip> = halo2_ecc::ecc::BaseFieldEccChip<'chip, G1Affine>;
pub type Halo2Loader<'chip> = loader::halo2::Halo2Loader<G1Affine, BaseFieldEccChip<'chip>>;

#[allow(clippy::type_complexity)]
/// Core function used in `synthesize` to aggregate multiple `snarks`.
///  
/// Returns the assigned instances of previous snarks and the new final pair that needs to be verified in a pairing check.
/// For each previous snark, we concatenate all instances into a single vector. We return a vector of vectors,
/// one vector per snark, for convenience.
pub fn aggregate<'a, AS>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[Snark],
    as_proof: &[u8],
) -> (Vec<Vec<AssignedValue<Fr>>>, KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>)
where
    AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
            VerifyingKey = KzgAsVerifyingKey,
        >,
{
    let assign_instances = |instances: &[Vec<Fr>]| {
        instances
            .iter()
            .map(|instances| {
                instances.iter().map(|instance| loader.assign_scalar(*instance)).collect_vec()
            })
            .collect_vec()
    };

    let mut previous_instances = Vec::with_capacity(snarks.len());
    // to avoid re-loading the spec each time, we create one transcript and clear the stream
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader<'a>>, &[u8]>::from_spec(
        loader,
        &[],
        POSEIDON_SPEC.clone(),
    );

    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let protocol = snark.protocol.loaded(loader);
            let instances = assign_instances(&snark.instances);

            // read the transcript and perform Fiat-Shamir
            // run through verification computation and produce the final pair `succinct`
            transcript.new_stream(snark.proof());
            let proof = PlonkSuccinctVerifier::<AS>::read_proof(
                svk,
                &protocol,
                &instances,
                &mut transcript,
            )
            .unwrap();
            let accumulator =
                PlonkSuccinctVerifier::<AS>::verify(svk, &protocol, &instances, &proof).unwrap();

            previous_instances.push(
                instances.into_iter().flatten().map(|scalar| scalar.into_assigned()).collect(),
            );

            accumulator
        })
        .collect_vec();

    let accumulator = if accumulators.len() > 1 {
        transcript.new_stream(as_proof);
        let proof = <AS as AccumulationScheme<_, _>>::read_proof(
            &Default::default(),
            &accumulators,
            &mut transcript,
        )
        .unwrap();
        <AS as AccumulationScheme<_, _>>::verify(&Default::default(), &accumulators, &proof)
            .unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    (previous_instances, accumulator)
}

#[derive(Serialize, Deserialize)]
pub struct AggregationConfigParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
}

impl AggregationConfigParams {
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        serde_json::from_reader(File::open(path).expect("Aggregation config path does not exist"))
            .unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct RangeWithInstanceConfig<F: ScalarField> {
    pub range: RangeConfig<F>,
    pub instance: Column<Instance>,
}

/// This is an extension of [`RangeCircuitBuilder`] that adds support for public instances (aka public inputs+outputs)
///
/// The intended design is that a [`GateThreadBuilder`] is populated and then produces some assigned instances, which are supplied as `assigned_instances` to this struct.
/// The [`Circuit`] implementation for this struct will then expose these instances and constrain them using the Halo2 API.
#[derive(Clone, Debug)]
pub struct RangeWithInstanceCircuitBuilder<F: ScalarField> {
    pub circuit: RangeCircuitBuilder<F>,
    pub assigned_instances: Vec<AssignedValue<F>>,
}

impl<F: ScalarField> RangeWithInstanceCircuitBuilder<F> {
    pub fn keygen(
        builder: GateThreadBuilder<F>,
        assigned_instances: Vec<AssignedValue<F>>,
    ) -> Self {
        Self { circuit: RangeCircuitBuilder::keygen(builder), assigned_instances }
    }

    pub fn mock(builder: GateThreadBuilder<F>, assigned_instances: Vec<AssignedValue<F>>) -> Self {
        Self { circuit: RangeCircuitBuilder::mock(builder), assigned_instances }
    }

    pub fn prover(
        builder: GateThreadBuilder<F>,
        assigned_instances: Vec<AssignedValue<F>>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self {
        Self { circuit: RangeCircuitBuilder::prover(builder, break_points), assigned_instances }
    }

    pub fn new(circuit: RangeCircuitBuilder<F>, assigned_instances: Vec<AssignedValue<F>>) -> Self {
        Self { circuit, assigned_instances }
    }

    pub fn config(&self, k: u32, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.circuit.0.builder.borrow().config(k as usize, minimum_rows)
    }

    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.circuit.0.break_points.borrow().clone()
    }

    pub fn instance_count(&self) -> usize {
        self.assigned_instances.len()
    }

    pub fn instance(&self) -> Vec<F> {
        self.assigned_instances.iter().map(|v| *v.value()).collect()
    }
}

#[derive(Clone, Debug)]
pub struct AggregationCircuit {
    pub inner: RangeWithInstanceCircuitBuilder<Fr>,
    // the public instances from previous snarks that were aggregated, now collected as PRIVATE assigned values
    // the user can optionally append these to `inner.assigned_instances` to expose them
    pub previous_instances: Vec<Vec<AssignedValue<Fr>>>,
    // accumulation scheme proof, private input
    pub as_proof: Vec<u8>, // not sure this needs to be stored, keeping for now
}

// trait just so we can have a generic that is either SHPLONK or GWC
pub trait Halo2KzgAccumulationScheme<'a> = PolynomialCommitmentScheme<
        G1Affine,
        Rc<Halo2Loader<'a>>,
        VerifyingKey = Svk,
        Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
    > + AccumulationScheme<
        G1Affine,
        Rc<Halo2Loader<'a>>,
        Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        VerifyingKey = KzgAsVerifyingKey,
    > + PolynomialCommitmentScheme<
        G1Affine,
        NativeLoader,
        VerifyingKey = Svk,
        Output = KzgAccumulator<G1Affine, NativeLoader>,
    > + AccumulationScheme<
        G1Affine,
        NativeLoader,
        Accumulator = KzgAccumulator<G1Affine, NativeLoader>,
        VerifyingKey = KzgAsVerifyingKey,
    > + AccumulationSchemeProver<G1Affine, ProvingKey = KzgAsProvingKey<G1Affine>>;

impl AggregationCircuit {
    /// Given snarks, this creates a circuit and runs the `GateThreadBuilder` to verify all the snarks.
    /// By default, the returned circuit has public instances equal to the limbs of the pair of elliptic curve points, referred to as the `accumulator`, that need to be verified in a final pairing check.
    ///
    /// The user can optionally modify the circuit after calling this function to add more instances to `assigned_instances` to expose.
    ///
    /// Warning: will fail silently if `snarks` were created using a different multi-open scheme than `AS`
    /// where `AS` can be either [`crate::SHPLONK`] or [`crate::GWC`] (for original PLONK multi-open scheme)
    pub fn new<AS>(
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark>,
    ) -> Self
    where
        AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    {
        let svk: Svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        let mut transcript_read =
            PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
        // TODO: the snarks can probably store these accumulators
        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                transcript_read.new_stream(snark.proof());
                let proof = PlonkSuccinctVerifier::<AS>::read_proof(
                    &svk,
                    &snark.protocol,
                    &snark.instances,
                    &mut transcript_read,
                )
                .unwrap();
                PlonkSuccinctVerifier::<AS>::verify(&svk, &snark.protocol, &snark.instances, &proof)
                    .unwrap()
            })
            .collect_vec();

        let (_accumulator, as_proof) = {
            let mut transcript_write = PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(
                vec![],
                POSEIDON_SPEC.clone(),
            );
            let rng = StdRng::from_entropy();
            let accumulator =
                AS::create_proof(&Default::default(), &accumulators, &mut transcript_write, rng)
                    .unwrap();
            (accumulator, transcript_write.finalize())
        };

        // create thread builder and run aggregation witness gen
        let builder = match stage {
            CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
            CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
            CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
        };
        // create halo2loader
        let range = RangeChip::<Fr>::default(lookup_bits);
        let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
        let ecc_chip = BaseFieldEccChip::new(&fp_chip);
        let loader = Halo2Loader::new(ecc_chip, builder);

        let (previous_instances, accumulator) =
            aggregate::<AS>(&svk, &loader, &snarks, as_proof.as_slice());
        let lhs = accumulator.lhs.assigned();
        let rhs = accumulator.rhs.assigned();
        let assigned_instances = lhs
            .x
            .truncation
            .limbs
            .iter()
            .chain(lhs.y.truncation.limbs.iter())
            .chain(rhs.x.truncation.limbs.iter())
            .chain(rhs.y.truncation.limbs.iter())
            .copied()
            .collect_vec();

        #[cfg(debug_assertions)]
        {
            let KzgAccumulator { lhs, rhs } = _accumulator;
            let instances =
                [lhs.x, lhs.y, rhs.x, rhs.y].map(fe_to_limbs::<_, Fr, LIMBS, BITS>).concat();
            for (lhs, rhs) in instances.iter().zip(assigned_instances.iter()) {
                assert_eq!(lhs, rhs.value());
            }
        }

        let builder = loader.take_ctx();
        let circuit = match stage {
            CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder),
            CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder),
            CircuitBuilderStage::Prover => {
                RangeCircuitBuilder::prover(builder, break_points.unwrap())
            }
        };
        let inner = RangeWithInstanceCircuitBuilder::new(circuit, assigned_instances);
        Self { inner, previous_instances, as_proof }
    }

    pub fn public<AS>(
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark>,
        has_prev_accumulator: bool,
    ) -> Self
    where
        AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    {
        let mut private = Self::new::<AS>(stage, break_points, lookup_bits, params, snarks);
        private.expose_previous_instances(has_prev_accumulator);
        private
    }

    // this function is for convenience
    /// `params` should be the universal trusted setup to be used for the aggregation circuit, not the one used to generate the previous snarks, although we assume both use the same generator g[0]
    pub fn keygen<AS>(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self
    where
        AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    {
        let lookup_bits = params.k() as usize - 1; // almost always we just use the max lookup bits possible, which is k - 1 because of blinding factors
        let circuit =
            Self::new::<AS>(CircuitBuilderStage::Keygen, None, lookup_bits, params, snarks);
        circuit.config(params.k(), Some(10));
        set_var("LOOKUP_BITS", lookup_bits.to_string());
        circuit
    }

    // this function is for convenience
    pub fn prover<AS>(
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark>,
        break_points: MultiPhaseThreadBreakPoints,
    ) -> Self
    where
        AS: for<'a> Halo2KzgAccumulationScheme<'a>,
    {
        let lookup_bits: usize = var("LOOKUP_BITS").expect("LOOKUP_BITS not set").parse().unwrap();
        let circuit = Self::new::<AS>(
            CircuitBuilderStage::Prover,
            Some(break_points),
            lookup_bits,
            params,
            snarks,
        );
        let minimum_rows = var("MINIMUM_ROWS").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
        circuit.config(params.k(), Some(minimum_rows));
        set_var("LOOKUP_BITS", lookup_bits.to_string());
        circuit
    }

    /// Re-expose the previous public instances of aggregated snarks again.
    /// If `hash_prev_accumulator` is true, then we assume all aggregated snarks were themselves
    /// aggregation snarks, and we exclude the old accumulators from the public input.
    pub fn expose_previous_instances(&mut self, has_prev_accumulator: bool) {
        let start = (has_prev_accumulator as usize) * 4 * LIMBS;
        for prev in self.previous_instances.iter() {
            self.inner.assigned_instances.extend_from_slice(&prev[start..]);
        }
    }

    pub fn as_proof(&self) -> &[u8] {
        &self.as_proof[..]
    }

    pub fn config(&self, k: u32, minimum_rows: Option<usize>) -> FlexGateConfigParams {
        self.inner.config(k, minimum_rows)
    }

    pub fn break_points(&self) -> MultiPhaseThreadBreakPoints {
        self.inner.break_points()
    }

    pub fn instance_count(&self) -> usize {
        self.inner.instance_count()
    }

    pub fn instance(&self) -> Vec<Fr> {
        self.inner.instance()
    }
}

impl<F: ScalarField> Circuit<F> for RangeWithInstanceCircuitBuilder<F> {
    type Config = RangeWithInstanceConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<F>) -> Self::Config {
        let range = RangeCircuitBuilder::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        RangeWithInstanceConfig { range, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        // copied from RangeCircuitBuilder::synthesize but with extra logic to expose public instances
        let range = config.range;
        let circuit = &self.circuit.0;
        range.load_lookup_table(&mut layouter).expect("load lookup table should not fail");

        // we later `take` the builder, so we need to save this value
        let witness_gen_only = circuit.builder.borrow().witness_gen_only();
        let mut assigned_advices = HashMap::new();

        let mut first_pass = SKIP_FIRST_PASS;
        layouter
            .assign_region(
                || "RangeWithInstanceCircuitBuilder",
                |mut region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    // only support FirstPhase in this Builder because getting challenge value requires more specialized witness generation during synthesize
                    if !witness_gen_only {
                        // clone the builder so we can re-use the circuit for both vk and pk gen
                        let builder = circuit.builder.borrow();
                        let assignments = builder.assign_all(
                            &range.gate,
                            &range.lookup_advice,
                            &range.q_lookup,
                            &mut region,
                            Default::default(),
                        );
                        *circuit.break_points.borrow_mut() = assignments.break_points;
                        assigned_advices = assignments.assigned_advices;
                    } else {
                        #[cfg(feature = "display")]
                        let start0 = std::time::Instant::now();
                        let builder = circuit.builder.take();
                        let break_points = circuit.break_points.take();
                        for (phase, (threads, break_points)) in builder
                            .threads
                            .into_iter()
                            .zip(break_points.into_iter())
                            .enumerate()
                            .take(1)
                        {
                            assign_threads_in(
                                phase,
                                threads,
                                &range.gate,
                                &range.lookup_advice[phase],
                                &mut region,
                                break_points,
                            );
                        }
                        #[cfg(feature = "display")]
                        println!("assign threads in {:?}", start0.elapsed());
                    }
                    Ok(())
                },
            )
            .unwrap();

        if !witness_gen_only {
            // expose public instances
            let mut layouter = layouter.namespace(|| "expose");
            for (i, instance) in self.assigned_instances.iter().enumerate() {
                let cell = instance.cell.unwrap();
                let (cell, _) = assigned_advices
                    .get(&(cell.context_id, cell.offset))
                    .expect("instance not assigned");
                layouter.constrain_instance(*cell, config.instance, i)?;
            }
        }
        Ok(())
    }
}

impl<F: ScalarField> CircuitExt<F> for RangeWithInstanceCircuitBuilder<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instance_count()]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![self.instance()]
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        config.range.gate.basic_gates[0].iter().map(|gate| gate.q_enable).collect()
    }
}

impl Circuit<Fr> for AggregationCircuit {
    type Config = RangeWithInstanceConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        RangeWithInstanceCircuitBuilder::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        self.inner.synthesize(config, layouter)
    }
}

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        self.inner.num_instance()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.inner.instances()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        RangeWithInstanceCircuitBuilder::selectors(config)
    }
}

pub fn load_verify_circuit_degree() -> u32 {
    let path = std::env::var("VERIFY_CONFIG")
        .unwrap_or_else(|_| "./configs/verify_circuit.config".to_string());
    let params: AggregationConfigParams = serde_json::from_reader(
        File::open(path.as_str()).unwrap_or_else(|_| panic!("{path} does not exist")),
    )
    .unwrap();
    params.degree
}
