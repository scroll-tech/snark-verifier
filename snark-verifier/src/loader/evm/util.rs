use crate::{
    cost::Cost,
    util::{arithmetic::PrimeField, Itertools},
};
use anyhow::{anyhow, Result};
use ethereum_types::U256;
use regex::Regex;
use std::{
    cmp::Ordering,
    fmt,
    io::Write,
    iter,
    process::{Command, Stdio},
};

pub(crate) mod executor;

pub use executor::ExecutorBuilder;

const MAX_SOLC_VERSION: SolcVersion = SolcVersion::new(0, 8, 19);

/// Memory chunk in EVM.
#[derive(Debug)]
pub struct MemoryChunk {
    ptr: usize,
    len: usize,
}

impl MemoryChunk {
    pub(crate) fn new(ptr: usize) -> Self {
        Self { ptr, len: 0 }
    }

    pub(crate) fn ptr(&self) -> usize {
        self.ptr
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn end(&self) -> usize {
        self.ptr + self.len
    }

    pub(crate) fn reset(&mut self, ptr: usize) {
        self.ptr = ptr;
        self.len = 0;
    }

    pub(crate) fn extend(&mut self, size: usize) {
        self.len += size;
    }
}

/// Convert a [`PrimeField`] into a [`U256`].
/// Assuming fields that implement traits in crate `ff` always have
/// little-endian representation.
pub fn fe_to_u256<F>(f: F) -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_little_endian(f.to_repr().as_ref())
}

/// Convert a [`U256`] into a [`PrimeField`].
pub fn u256_to_fe<F>(value: U256) -> F
where
    F: PrimeField<Repr = [u8; 32]>,
{
    let value = value % modulus::<F>();
    let mut repr = F::Repr::default();
    value.to_little_endian(repr.as_mut());
    F::from_repr(repr).unwrap()
}

/// Returns modulus of [`PrimeField`] as [`U256`].
pub fn modulus<F>() -> U256
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U256::from_little_endian((-F::one()).to_repr().as_ref()) + 1
}

/// Encode instances and proof into calldata.
pub fn encode_calldata<F>(instances: &[Vec<F>], proof: &[u8]) -> Vec<u8>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    iter::empty()
        .chain(
            instances
                .iter()
                .flatten()
                .flat_map(|value| value.to_repr().as_ref().iter().rev().cloned().collect_vec()),
        )
        .chain(proof.iter().cloned())
        .collect()
}

/// Estimate gas cost with given [`Cost`].
pub fn estimate_gas(cost: Cost) -> usize {
    let proof_size = cost.num_commitment * 64 + (cost.num_evaluation + cost.num_instance) * 32;

    let intrinsic_cost = 21000;
    let calldata_cost = (proof_size as f64 * 15.25).ceil() as usize;
    let ec_operation_cost = 113100 + (cost.num_msm - 2) * 6350;

    intrinsic_cost + calldata_cost + ec_operation_cost
}

/// Compile given yul `code` into deployment bytecode.
pub fn compile_yul(code: &str) -> Vec<u8> {
    match SolcVersion::from_cmd() {
        Ok(version) => {
            assert!(version <= MAX_SOLC_VERSION, "solc version must be `<= {}`", MAX_SOLC_VERSION)
        }
        Err(err) => log::error!("{}", err),
    };

    let mut cmd = Command::new("solc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .arg("--bin")
        .arg("--yul")
        .arg("-")
        .spawn()
        .unwrap();
    cmd.stdin.take().unwrap().write_all(code.as_bytes()).unwrap();
    let output = cmd.wait_with_output().unwrap().stdout;
    let binary = *split_by_ascii_whitespace(&output).last().unwrap();
    hex::decode(binary).unwrap()
}

fn split_by_ascii_whitespace(bytes: &[u8]) -> Vec<&[u8]> {
    let mut split = Vec::new();
    let mut start = None;
    for (idx, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_whitespace() {
            if let Some(start) = start.take() {
                split.push(&bytes[start..idx]);
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }
    split
}

/// Solidity compiler version
#[derive(Debug, PartialEq)]
struct SolcVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl fmt::Display for SolcVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for SolcVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            [(self.major, other.major), (self.minor, other.minor), (self.patch, other.patch)]
                .iter()
                .fold(Ordering::Equal, |acc, (lhs, rhs)| acc.then(lhs.cmp(rhs))),
        )
    }
}

impl SolcVersion {
    const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self { major, minor, patch }
    }

    fn from_cmd() -> Result<Self> {
        let output = Command::new("solc").arg("--version").output()?;
        let output = String::from_utf8_lossy(output.stdout.as_slice());

        let regex = Regex::new(r"Version: (\d+)\.(\d+)\.(\d+)")?;

        regex
            .captures(&output)
            .and_then(|version| {
                match [1, 2, 3].map(|i| version.get(i).and_then(|v| v.as_str().parse::<u64>().ok()))
                {
                    [Some(major), Some(minor), Some(patch)] => Some(Self::new(major, minor, patch)),
                    _ => None,
                }
            })
            .ok_or_else(|| anyhow!("Failed to parse solc version: {}", output))
    }
}
