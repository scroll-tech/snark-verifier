use eth_types::Field;
use halo2_base::halo2_proofs::plonk::Selector;
use zkevm_circuits::super_circuit::SuperCircuit;

use crate::CircuitExt;

impl<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > CircuitExt<F> for SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
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
