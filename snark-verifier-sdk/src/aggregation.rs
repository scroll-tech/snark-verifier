#![allow(clippy::clone_on_copy)]
use crate::{
    types::{BaseFieldEccChip, Halo2Loader, Plonk, PoseidonTranscript, POSEIDON_SPEC},
    SnarkWitness,
};
#[cfg(feature = "display")]
use ark_std::end_timer;
#[cfg(feature = "display")]
use ark_std::start_timer;
use halo2_base::{
    halo2_proofs::{
        circuit::Value,
        halo2curves::bn256::{Fq, Fr, G1Affine},
    },
    AssignedValue,
};
use itertools::Itertools;
use snark_verifier::{
    loader::halo2::{
        halo2_ecc::{ecc::EccChip, fields::fp::FpConfig},
        EccInstructions,
    },
    pcs::{
        kzg::{KzgAccumulator, KzgAs},
        AccumulationScheme, MultiOpenScheme, PolynomialCommitmentScheme,
    },
    verifier::PlonkVerifier,
};
use std::{fs::File, rc::Rc};

use config::AggregationConfigParams;

pub mod aggregation_circuit;
pub mod config;
pub mod multi_aggregation_circuit;

pub fn load_verify_circuit_degree() -> u32 {
    let path = std::env::var("VERIFY_CONFIG")
        .unwrap_or_else(|_| "./configs/verify_circuit.config".to_string());
    let params: AggregationConfigParams = serde_json::from_reader(
        File::open(path.as_str()).unwrap_or_else(|_| panic!("{path} does not exist")),
    )
    .unwrap();
    params.degree
}

pub fn flatten_accumulator(
    accumulator: KzgAccumulator<G1Affine, Rc<Halo2Loader>>,
) -> Vec<AssignedValue<Fr>> {
    let KzgAccumulator { lhs, rhs } = accumulator;
    let lhs = lhs.into_assigned();
    let rhs = rhs.into_assigned();

    lhs.x
        .truncation
        .limbs
        .into_iter()
        .chain(lhs.y.truncation.limbs)
        .chain(rhs.x.truncation.limbs)
        .chain(rhs.y.truncation.limbs)
        .collect()
}

type AssignedInstances<'a> =
    Vec<Vec<<BaseFieldEccChip as EccInstructions<'a, G1Affine>>::AssignedScalar>>;
type KzgAcc<'a> = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>;
type AssignedEcPoints<'a> =
    Vec<Vec<<EccChip<Fr, FpConfig<Fr, Fq>> as EccInstructions<'a, G1Affine>>::AssignedEcPoint>>;
type AssignedScalars<'a> =
    Vec<Option<<EccChip<Fr, FpConfig<Fr, Fq>> as EccInstructions<'a, G1Affine>>::AssignedScalar>>;

/// Core function used in `synthesize` to aggregate multiple `snarks`.
///  
/// Returns the assigned instances of previous snarks and the new final pair that needs to be verified in a pairing check.
/// For each previous snark, we concatenate all instances into a single vector. We return a vector of vectors,
/// one vector per snark, for convenience.
#[allow(clippy::type_complexity)]
pub fn aggregate_hybrid<'a, PCS>(
    svk: &PCS::SuccinctVerifyingKey,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness],
    as_proof: Value<&'_ [u8]>,
) -> (AssignedInstances<'a>, KzgAcc<'a>, AssignedEcPoints<'a>, AssignedScalars<'a>)
where
    PCS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + MultiOpenScheme<G1Affine, Rc<Halo2Loader<'a>>>,
{
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances.iter().map(|instance| loader.assign_scalar(*instance)).collect_vec()
            })
            .collect_vec()
    };

    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader<'a>>, _>::from_spec(
        loader,
        Value::unknown(),
        POSEIDON_SPEC.clone(),
    );

    let mut previous_instances = Vec::with_capacity(snarks.len());
    let mut preprocessed_polys = Vec::with_capacity(snarks.len());
    let mut transcript_init_states = Vec::with_capacity(snarks.len());
    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            // The SNARK protocol's preprocessed polynomials and the initial state of the
            // prover/verifier's transcripts are loaded as witnesses.
            //
            // This allows us to aggregate SNARKs that may have been generated using one or more
            // circuits.
            //
            // Note: Its important to further constrain the assigned preprocessed polynomial commitments
            // and the assigned transcript initial state to belong to a fixed expected set.
            let protocol = snark.protocol.loaded_preprocessed_as_witness(loader);

            // TODO use 1d vector
            let instances = assign_instances(&snark.instances);

            // read the transcript and perform Fiat-Shamir
            // run through verification computation and produce the final pair `succinct`
            transcript.new_stream(snark.proof());
            let proof = Plonk::<PCS>::read_proof(svk, &protocol, &instances, &mut transcript);
            let accumulator = Plonk::<PCS>::succinct_verify(svk, &protocol, &instances, &proof);

            previous_instances.push(
                instances.into_iter().flatten().map(|scalar| scalar.into_assigned()).collect(),
            );
            preprocessed_polys
                .push(protocol.preprocessed.into_iter().map(|ec| ec.into_assigned()).collect());
            transcript_init_states
                .push(protocol.transcript_initial_state.map(|s| s.into_assigned()));

            accumulator
        })
        .collect_vec();

    let accumulator = if accumulators.len() > 1 {
        transcript.new_stream(as_proof);
        let proof =
            KzgAs::<PCS>::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
        KzgAs::<PCS>::verify(&Default::default(), &accumulators, &proof).unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    (previous_instances, accumulator, preprocessed_polys, transcript_init_states)
}

#[allow(clippy::type_complexity)]
/// Core function used in `synthesize` to aggregate multiple `snarks`.
///  
/// Returns the assigned instances of previous snarks and the new final pair that needs to be verified in a pairing check.
/// For each previous snark, we concatenate all instances into a single vector. We return a vector of vectors,
/// one vector per snark, for convenience.
pub fn aggregate<'a, PCS>(
    svk: &PCS::SuccinctVerifyingKey,
    loader: &Rc<Halo2Loader<'a>>,
    snarks: &[SnarkWitness],
    as_proof: Value<&'_ [u8]>,
) -> (AssignedInstances<'a>, KzgAcc<'a>)
where
    PCS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + MultiOpenScheme<G1Affine, Rc<Halo2Loader<'a>>>,
{
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances.iter().map(|instance| loader.assign_scalar(*instance)).collect_vec()
            })
            .collect_vec()
    };

    // TODO pre-allocate capacity better
    let mut previous_instances = Vec::with_capacity(snarks.len());
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader<'a>>, _>::from_spec(
        loader,
        Value::unknown(),
        POSEIDON_SPEC.clone(),
    );

    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let protocol = snark.protocol.loaded(loader);
            // TODO use 1d vector
            let instances = assign_instances(&snark.instances);

            // read the transcript and perform Fiat-Shamir
            // run through verification computation and produce the final pair `succinct`
            transcript.new_stream(snark.proof());
            let proof = Plonk::<PCS>::read_proof(svk, &protocol, &instances, &mut transcript);
            let accumulator = Plonk::<PCS>::succinct_verify(svk, &protocol, &instances, &proof);

            previous_instances.push(
                instances.into_iter().flatten().map(|scalar| scalar.into_assigned()).collect(),
            );

            accumulator
        })
        .collect_vec();

    let accumulator = if accumulators.len() > 1 {
        transcript.new_stream(as_proof);
        let proof =
            KzgAs::<PCS>::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
        KzgAs::<PCS>::verify(&Default::default(), &accumulators, &proof).unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    (previous_instances, accumulator)
}
