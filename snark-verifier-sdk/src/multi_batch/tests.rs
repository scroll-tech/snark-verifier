use ark_std::test_rng;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use itertools::Itertools;
use rand::Rng;
use zkevm_circuits::tx_circuit::GroupField;

use super::hash::{deserialize_instances, serialize_instances};

#[test]
fn test_instance_serialization() {
    let max_row = 100;
    let max_col = 100;
    let mut rng = test_rng();

    for _ in 0..100 {
        let instance = random_instance(&mut rng, max_row, max_col);
        let serialized = serialize_instances(&instance);
        let instance_rec = deserialize_instances(&serialized);
        assert_eq!(instance, instance_rec)
    }
}

fn random_instance<R: Rng + Send>(rng: &mut R, max_row: usize, max_col: usize) -> Vec<Vec<Fr>> {
    let num_cols = rng.next_u32() as usize % max_row + 1;
    let mut res = vec![];

    for _ in 0..num_cols {
        let col_size = rng.next_u32() as usize % max_col + 1;
        let cur_col = (0..col_size).map(|_| Fr::random(&mut *rng)).collect_vec();
        res.push(cur_col);
    }

    res
}
