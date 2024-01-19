use halo2_base::halo2_proofs;
use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Fixed, Instance, TableColumn},
    poly::Rotation,
};
use test_circuit_1::TestCircuit1;
use test_circuit_2::TestCircuit2;

mod evm_verifier;
mod single_layer_aggregation;
mod test_circuit_1;
mod test_circuit_2;
mod two_layer_aggregation;

#[derive(Clone, Copy)]
pub struct StandardPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    #[allow(dead_code)]
    instance: Column<Instance>,
    table: TableColumn,
}

impl StandardPlonkConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();
        let table = meta.lookup_table_column();

        [a, b, c].map(|column| meta.enable_equality(column));

        meta.create_gate(
            "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
            |meta| {
                let [a, b, c] = [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|column| meta.query_fixed(column, Rotation::cur()));
                let instance = meta.query_instance(instance, Rotation::cur());
                Some(
                    q_a * a.clone()
                        + q_b * b.clone()
                        + q_c * c
                        + q_ab * a * b
                        + constant
                        + instance,
                )
            },
        );

        // Lookup for multiple times to test mv-lookup.
        (0..5).for_each(|_| {
            meta.lookup("lookup a", |meta| {
                let a = meta.query_advice(a, Rotation::cur());
                vec![(a, table)]
            })
        });

        StandardPlonkConfig { a, b, c, q_a, q_b, q_c, q_ab, constant, instance, table }
    }
}
