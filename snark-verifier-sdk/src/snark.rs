use halo2_base::halo2_proofs;
use halo2_proofs::{
    circuit::Value,
    halo2curves::bn256::{Fr, G1Affine},
};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use snark_verifier::Protocol;

mod mock;

/// A Snark struct is all one may need to generate witnesses for an aggregation circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snark {
    pub protocol: Protocol<G1Affine>,
    pub instances: Vec<Vec<Fr>>,
    pub proof: Vec<u8>,
}

impl Snark {
    pub fn new(protocol: Protocol<G1Affine>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> Self {
        Self { protocol, instances, proof }
    }
}

impl From<Snark> for SnarkWitness {
    fn from(snark: Snark) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

/// A SnarkWitness struct is a snark converted to witness.
#[derive(Clone, Debug)]
pub struct SnarkWitness {
    pub protocol: Protocol<G1Affine>,
    pub instances: Vec<Vec<Value<Fr>>>,
    pub proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    /// Initialize an empty SnarkWitness with a same struct as self.
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }

    /// Expose the proof of the witness.
    pub fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}
