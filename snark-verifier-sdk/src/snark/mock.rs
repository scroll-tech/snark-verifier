//! Mock Snark
use crate::{circuit_ext::CircuitExt, types::PoseidonTranscript};

use super::Snark;
#[cfg(feature = "display")]
use ark_std::end_timer;
#[cfg(feature = "display")]
use ark_std::start_timer;
use halo2_base::halo2_proofs::{self};
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        group::ff::Field,
    },
    plonk::{keygen_vk, Circuit, ConstraintSystem, Error, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier::{
    cost::CostEstimation,
    loader::native::NativeLoader,
    pcs::{
        MultiOpenScheme, {self},
    },
    system::halo2::{compile, Config},
    util::transcript::TranscriptWrite,
    verifier::PlonkProof,
};
use std::marker::PhantomData;

struct CsProxy<F, C>(PhantomData<(F, C)>);

impl<F: Field, C: CircuitExt<F>> Circuit<F> for CsProxy<F, C> {
    type Config = C::Config;
    type FloorPlanner = C::FloorPlanner;

    fn without_witnesses(&self) -> Self {
        CsProxy(PhantomData)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        C::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // when `C` has simple selectors, we tell `CsProxy` not to over-optimize the selectors (e.g., compressing them  all into one) by turning all selectors on in the first row
        // currently this only works if all simple selector columns are used in the actual circuit and there are overlaps amongst all enabled selectors (i.e., the actual circuit will not optimize constraint system further)
        layouter.assign_region(
            || "",
            |mut region| {
                for q in C::selectors(&config).iter() {
                    q.enable(&mut region, 0)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Generate a Snark for a ConcreteCircuit
pub fn gen_dummy_snark<ConcreteCircuit, MOS>(
    params: &ParamsKZG<Bn256>,
    vk: Option<&VerifyingKey<G1Affine>>,
    num_instance: Vec<usize>,
) -> Snark
where
    ConcreteCircuit: CircuitExt<Fr>,
    MOS: MultiOpenScheme<G1Affine, NativeLoader>
        + CostEstimation<G1Affine, Input = Vec<pcs::Query<Fr>>>,
{
    let dummy_vk = vk
        .is_none()
        .then(|| keygen_vk(params, &CsProxy::<Fr, ConcreteCircuit>(PhantomData)).unwrap());
    let protocol = compile(
        params,
        vk.or(dummy_vk.as_ref()).unwrap(),
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
    );
    let instances = num_instance.into_iter().map(|n| vec![Fr::default(); n]).collect();
    let proof = {
        let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
        for _ in 0..protocol
            .num_witness
            .iter()
            .chain(Some(&protocol.quotient.num_chunk()))
            .sum::<usize>()
        {
            transcript.write_ec_point(G1Affine::default()).unwrap();
        }
        for _ in 0..protocol.evaluations.len() {
            transcript.write_scalar(Fr::default()).unwrap();
        }
        let queries = PlonkProof::<G1Affine, NativeLoader, MOS>::empty_queries(&protocol);
        for _ in 0..MOS::estimate_cost(&queries).num_commitment {
            transcript.write_ec_point(G1Affine::default()).unwrap();
        }
        transcript.finalize()
    };

    Snark::new(protocol, instances, proof)
}
