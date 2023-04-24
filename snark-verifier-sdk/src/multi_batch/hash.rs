//! This module implements the sha2 circuit that glues together all the instances
//!
//! Each instance is a Vec<Vec<Fr>> which will be serialized via the following:
//! - Prefix:
//!     - num_ins: number of instance vectors; 8 bytes
//!     - for each j in num_ins, the number of Fr elements in the instance vector: 8 bytes each
//! - actual data:
//!     - serialized Fr Elements
//!

use halo2_base::halo2_proofs::halo2curves::bn256::Fr;

/// Serialize an instance from the snark
pub(crate) fn serialize_instances(instance: &[Vec<Fr>]) -> Vec<u8> {
    let mut buf: Vec<u8> = vec![];

    // write the prefix
    let num_ins = instance.len();
    buf.extend_from_slice(num_ins.to_le_bytes().as_ref());
    for instance_column in instance.iter() {
        buf.extend_from_slice(instance_column.len().to_le_bytes().as_ref());
    }

    // write the actual data
    for instance_column in instance.iter() {
        for element in instance_column.iter() {
            buf.extend_from_slice(element.to_bytes().as_slice())
        }
    }

    buf
}

/// Deserialize an instance for the snark
pub(crate) fn deserialize_instances(data: &[u8]) -> Vec<Vec<Fr>> {
    // the input data is at least 8 bytes
    assert!(data.len() >= 8);

    let mut res = vec![];
    let mut res_len = vec![];
    let num_ins =
        usize::from_le_bytes(data[0..8].try_into().expect("input data has incorrect length"));

    for i in 0..num_ins {
        res_len.push(usize::from_le_bytes(
            data[8 * (i + 1)..8 * (i + 2)].try_into().expect("input data has incorrect length"),
        ));
    }
    let total_fr_elements: usize = res_len.iter().sum();
    let pre_fix_len = num_ins * 8 + 8;
    assert_eq!(
        data.len(),
        total_fr_elements * 32 + num_ins * 8 + 8,
        "input data has incorrect length"
    );
    let mut ctr = 0;
    for i in 0..num_ins {
        let mut cur_column = vec![];
        for _ in 0..res_len[i] {
            cur_column.push(
                Fr::from_bytes(
                    data[pre_fix_len + 32 * ctr..pre_fix_len + 32 * ctr + 32]
                        .try_into()
                        .expect("input data has incorrect length"),
                )
                .unwrap(),
            );
            ctr += 1;
        }
        res.push(cur_column)
    }
    res
}
