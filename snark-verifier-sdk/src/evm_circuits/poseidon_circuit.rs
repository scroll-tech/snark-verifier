use eth_types::Field;
use halo2_base::halo2_proofs::plonk::Selector;
use zkevm_circuits::poseidon_circuit::PoseidonCircuit;

use crate::CircuitExt;

impl<F: Field> CircuitExt<F> for PoseidonCircuit<F> {
    /// Return the number of instances of the circuit.
    /// This may depend on extra circuit parameters but NOT on private witnesses.
    fn num_instance(&self) -> Vec<usize> {
        todo!()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        todo!()
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        todo!()
    }

    /// Output the simple selector columns (before selector compression) of the circuit
    fn selectors(_: &Self::Config) -> Vec<Selector> {
        todo!()
    }
}
