use halo2_base::halo2_proofs::{
    arithmetic::Field,
    plonk::{Circuit, Selector},
};

/// Circuit Extension trait that exposes related APIs.
pub trait CircuitExt<F: Field>: Circuit<F> {
    /// Return the number of instances of the circuit.
    /// This may depend on extra circuit parameters but NOT on private witnesses.
    fn num_instance(&self) -> Vec<usize> {
        vec![]
    }

    /// Expose the instance for the circuit
    fn instances(&self) -> Vec<Vec<F>> {
        vec![]
    }

    /// The indices of the accumulator
    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        None
    }

    /// Output the simple selector columns (before selector compression) of the circuit
    fn selectors(_: &Self::Config) -> Vec<Selector> {
        vec![]
    }
}
