use eth_types::Field;
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
        vec![0]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![]
    }
}
