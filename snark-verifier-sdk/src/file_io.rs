use std::{
    fs::{write, File},
    io::{BufReader, BufWriter},
    path::Path,
};

use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, ProvingKey},
    SerdeFormat,
};
use itertools::Itertools;
use snark_verifier::loader::evm::encode_calldata;

use crate::Snark;

/// Read instances from the disk
pub fn read_instances(path: impl AsRef<Path>) -> Result<Vec<Vec<Fr>>, bincode::Error> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let instances: Vec<Vec<[u8; 32]>> = bincode::deserialize_from(reader)?;
    instances
        .into_iter()
        .map(|instance_column| {
            instance_column
                .iter()
                .map(|bytes| {
                    Option::from(Fr::from_bytes(bytes)).ok_or(Box::new(bincode::ErrorKind::Custom(
                        "Invalid finite field point".to_owned(),
                    )))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

/// Write instances to the disk
pub fn write_instances(instances: &[&[Fr]], path: impl AsRef<Path>) {
    let instances: Vec<Vec<[u8; 32]>> = instances
        .iter()
        .map(|instance_column| instance_column.iter().map(|x| x.to_bytes()).collect_vec())
        .collect_vec();
    let f = BufWriter::new(File::create(path).unwrap());
    bincode::serialize_into(f, &instances).unwrap();
}

/// Read proving key from the disk
pub fn read_pk<C: Circuit<Fr>>(path: &Path) -> std::io::Result<ProvingKey<G1Affine>> {
    let f = File::open(path)?;
    #[cfg(feature = "display")]
    let read_time = start_timer!(|| format!("Reading pkey from {path:?}"));

    // BufReader is indeed MUCH faster than Read
    let mut bufreader = BufReader::new(f);
    // But it's even faster to load the whole file into memory first and then process,
    // HOWEVER this requires twice as much memory to initialize
    // let initial_buffer_size = f.metadata().map(|m| m.len() as usize + 1).unwrap_or(0);
    // let mut bufreader = Vec::with_capacity(initial_buffer_size);
    // f.read_to_end(&mut bufreader)?;
    let pk = ProvingKey::read::<_, C>(&mut bufreader, SerdeFormat::RawBytesUnchecked).unwrap();

    #[cfg(feature = "display")]
    end_timer!(read_time);

    Ok(pk)
}

/// Tries to deserialize a SNARK from the specified `path` using `bincode`.
///
/// WARNING: The user must keep track of whether the SNARK was generated using the GWC or SHPLONK multi-open scheme.
pub fn read_snark(path: impl AsRef<Path>) -> Result<Snark, bincode::Error> {
    let f = File::open(path).map_err(Box::<bincode::ErrorKind>::from)?;
    bincode::deserialize_from(f)
}

/// Write the calldata to disk
pub fn write_calldata(instances: &[Vec<Fr>], proof: &[u8], path: &Path) -> std::io::Result<String> {
    let calldata = encode_calldata(instances, proof);
    let calldata = hex::encode(calldata);
    write(path, &calldata)?;
    Ok(calldata)
}
