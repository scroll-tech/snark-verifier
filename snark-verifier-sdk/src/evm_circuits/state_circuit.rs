use eth_types::Field;
use zkevm_circuits::state_circuit::StateCircuit;

use crate::CircuitExt;

impl<F: Field> CircuitExt<F> for StateCircuit<F> {
    /// Return the number of instances of the circuit.
    /// This may depend on extra circuit parameters but NOT on private witnesses.
    fn num_instance(&self) -> Vec<usize> {
        vec![0]
    }

    fn instances(&self) -> Vec<Vec<F>> {
        vec![]
    }
}
