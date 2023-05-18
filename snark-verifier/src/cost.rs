//! Cost estimation.
use std::ops::Add;

/// Cost of verification.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Cost {
    /// Number of instances.
    pub num_instance: usize,
    /// Number of commitments in proof.
    pub num_commitment: usize,
    /// Number of evaluations in proof.
    pub num_evaluation: usize,
    /// Number of scalar multiplications to perform.
    pub num_msm: usize,
}

impl Cost {
    pub fn new(
        num_instance: usize,
        num_commitment: usize,
        num_evaluation: usize,
        num_msm: usize,
    ) -> Self {
        Self { num_instance, num_commitment, num_evaluation, num_msm }
    }
}

impl Add<Cost> for Cost {
    type Output = Cost;

    fn add(self, rhs: Cost) -> Self::Output {
        Cost::new(
            self.num_instance + rhs.num_instance,
            self.num_commitment + rhs.num_commitment,
            self.num_evaluation + rhs.num_evaluation,
            self.num_msm + rhs.num_msm,
        )
    }
}

/// For estimating cost of a verifier.
pub trait CostEstimation<T> {
    /// Input for [`CostEstimation::estimate_cost`].
    type Input;

    /// Estimate cost of verifier given the input.
    fn estimate_cost(input: &Self::Input) -> Cost;
}
