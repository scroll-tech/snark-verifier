//! Verifiers for polynomial commitment schemes.

use crate::{
    loader::{native::NativeLoader, Loader},
    util::{
        arithmetic::{CurveAffine, PrimeField},
        msm::Msm,
        transcript::{TranscriptRead, TranscriptWrite},
    },
    Error,
};
use rand::Rng;
use std::fmt::Debug;

pub mod kzg;

pub trait PolynomialCommitmentScheme<C, L>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
{
    type Accumulator: Clone + Debug;
}

/// Query to an oracle.
/// It assumes all queries are based on the same point, but with some `shift`.
#[derive(Clone, Debug)]
pub struct Query<F: PrimeField, T = ()> {
    /// Index of polynomial to query
    pub poly: usize,
    /// Shift of the query point.
    pub shift: F,
    /// Evaluation read from transcript.
    pub eval: T,
}

impl<F: PrimeField> Query<F> {
    /// Initialize [`Query`] without evaluation.
    pub fn new(poly: usize, shift: F) -> Self {
        Self { poly, shift, eval: () }
    }

    /// Returns [`Query`] with evaluation.
    pub fn with_evaluation<T>(self, eval: T) -> Query<F, T> {
        Query { poly: self.poly, shift: self.shift, eval }
    }
}

/// Polynomial commitment scheme verifier.
pub trait MultiOpenScheme<C, L>: PolynomialCommitmentScheme<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    /// Verifying key.
    type SuccinctVerifyingKey: Clone + Debug;
    /// Structured proof read from transcript.
    type Proof: Clone + Debug;

    /// Read [`PolynomialCommitmentScheme::Proof`] from transcript.
    fn read_proof<T>(
        svk: &Self::SuccinctVerifyingKey,
        queries: &[Query<C::Scalar>],
        transcript: &mut T,
    ) -> Self::Proof
    where
        T: TranscriptRead<C, L>;

    /// Verify [`MultiOpenScheme::Proof`] and output [`PolynomialCommitmentScheme::Accumulator`].
    fn succinct_verify(
        svk: &Self::SuccinctVerifyingKey,
        commitments: &[Msm<C, L>],
        point: &L::LoadedScalar,
        queries: &[Query<C::Scalar, L::LoadedScalar>],
        proof: &Self::Proof,
    ) -> Self::Accumulator;
}

/// Accumulation scheme verifier.
pub trait AccumulationScheme<C, L, PCS>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    /// Verifying key.
    type VerifyingKey: Clone + Debug;
    /// Structured proof read from transcript.
    type Proof: Clone + Debug;

    /// Read a [`AccumulationScheme::Proof`] from transcript.
    fn read_proof<T>(
        vk: &Self::VerifyingKey,
        instances: &[PCS::Accumulator],
        transcript: &mut T,
    ) -> Result<Self::Proof, Error>
    where
        T: TranscriptRead<C, L>;

    /// Verify old [`AccumulationScheme::Accumulator`]s are accumulated properly     
    /// into a new one with the [`AccumulationScheme::Proof`], and returns the
    /// new one as output.
    fn verify(
        vk: &Self::VerifyingKey,
        instances: &[PCS::Accumulator],
        proof: &Self::Proof,
    ) -> Result<PCS::Accumulator, Error>;
}

/// Accumulation scheme decider.
/// When accumulation is going to end, the decider will perform the check if the
/// final accumulator is valid or not, where the check is usually much more
/// expensive than accumulation verification.
pub trait Decider<C, L>: PolynomialCommitmentScheme<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    /// Deciding key. The key for decider for perform the final accumulator
    /// check.
    type DecidingKey: Clone + Debug;
    type Output: Clone + Debug;

    /// Decide if a [`AccumulationScheme::Accumulator`] is valid.
    fn decide(dk: &Self::DecidingKey, accumulator: Self::Accumulator) -> Self::Output;

    /// Decide if all [`AccumulationScheme::Accumulator`]s are valid.
    fn decide_all(dk: &Self::DecidingKey, accumulators: Vec<Self::Accumulator>) -> Self::Output;
}

/// Accumulation scheme prover.
pub trait AccumulationSchemeProver<C, PCS>: AccumulationScheme<C, NativeLoader, PCS>
where
    C: CurveAffine,
    PCS: PolynomialCommitmentScheme<C, NativeLoader>,
{
    /// Proving key.
    type ProvingKey: Clone + Debug;

    /// Create a proof that argues if old [`AccumulationScheme::Accumulator`]s
    /// are properly accumulated into the new one, and returns the new one as
    /// output.
    fn create_proof<T, R>(
        pk: &Self::ProvingKey,
        instances: &[PCS::Accumulator],
        transcript: &mut T,
        rng: R,
    ) -> Result<PCS::Accumulator, Error>
    where
        T: TranscriptWrite<C>,
        R: Rng;
}

/// Accumulator encoding.
pub trait AccumulatorEncoding<C, L, PCS>: Clone + Debug
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    fn from_repr(repr: &[&L::LoadedScalar]) -> Result<PCS::Accumulator, Error>;
}

impl<C, L, PCS> AccumulatorEncoding<C, L, PCS> for ()
where
    C: CurveAffine,
    L: Loader<C>,
    PCS: PolynomialCommitmentScheme<C, L>,
{
    fn from_repr(_: &[&L::LoadedScalar]) -> Result<PCS::Accumulator, Error> {
        unimplemented!()
    }
}
