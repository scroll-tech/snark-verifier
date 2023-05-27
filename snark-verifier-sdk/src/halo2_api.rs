use std::{
    fs::{self, File},
    io::BufWriter,
    path::Path,
};

use crate::{
    circuit_ext::CircuitExt,
    file_io::{read_pk, read_snark},
    read_instances,
    types::{PoseidonTranscript, POSEIDON_SPEC},
    write_instances, Snark,
};

#[cfg(feature = "display")]
use ark_std::end_timer;
#[cfg(feature = "display")]
use ark_std::start_timer;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            msm::DualMSM,
            multiopen::{ProverGWC, ProverSHPLONK, VerifierGWC, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, GuardKZG, SingleStrategy},
        },
        VerificationStrategy,
    },
    transcript::TranscriptReadBuffer,
    SerdeFormat, {self},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::native::NativeLoader,
    system::halo2::{compile, Config},
};

#[allow(clippy::let_and_return)]
pub fn gen_pk<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>, // TODO: read pk without params
    circuit: &C,
    path: Option<&Path>,
) -> ProvingKey<G1Affine> {
    if let Some(path) = path {
        if let Ok(pk) = read_pk::<C>(path) {
            return pk;
        }
    }
    #[cfg(feature = "display")]
    let pk_time = start_timer!(|| "Generating vkey & pkey");

    let vk = keygen_vk(params, circuit).unwrap();
    let pk = keygen_pk(params, vk, circuit).unwrap();

    #[cfg(feature = "display")]
    end_timer!(pk_time);

    if let Some(path) = path {
        #[cfg(feature = "display")]
        let write_time = start_timer!(|| format!("Writing pkey to {path:?}"));

        path.parent().and_then(|dir| fs::create_dir_all(dir).ok()).unwrap();
        let mut f = BufWriter::new(File::create(path).unwrap());
        pk.write(&mut f, SerdeFormat::RawBytesUnchecked).unwrap();

        #[cfg(feature = "display")]
        end_timer!(write_time);
    }
    pk
}

/// Generates a native proof using either SHPLONK or GWC proving method. Uses Poseidon for Fiat-Shamir.
///
/// Caches the instances and proof if `path = Some(instance_path, proof_path)` is specified.
pub fn gen_proof<'params, C, P, V>(
    // TODO: pass Option<&'params ParamsKZG<Bn256>> but hard to get lifetimes to work with `Cow`
    params: &'params ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
    rng: &mut (impl Rng + Send),
    path: Option<(&Path, &Path)>,
) -> Vec<u8>
where
    C: Circuit<Fr>,
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    #[cfg(debug_assertions)]
    {
        use halo2_proofs::poly::commitment::Params;
        halo2_proofs::dev::MockProver::run(params.k(), &circuit, instances.clone())
            .unwrap()
            .assert_satisfied();
    }

    if let Some((instance_path, proof_path)) = path {
        let cached_instances = read_instances(instance_path);
        if matches!(cached_instances, Ok(tmp) if tmp == instances) && proof_path.exists() {
            #[cfg(feature = "display")]
            let read_time = start_timer!(|| format!("Reading proof from {proof_path:?}"));

            let proof = fs::read(proof_path).unwrap();

            #[cfg(feature = "display")]
            end_timer!(read_time);
            return proof;
        }
    }

    let instances = instances.iter().map(Vec::as_slice).collect_vec();

    #[cfg(feature = "display")]
    let proof_time = start_timer!(|| "Create proof");

    let mut transcript =
        PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
    create_proof::<_, P, _, _, _, _>(params, pk, &[circuit], &[&instances], rng, &mut transcript)
        .unwrap();
    let proof = transcript.finalize();

    #[cfg(feature = "display")]
    end_timer!(proof_time);

    if let Some((instance_path, proof_path)) = path {
        write_instances(&instances, instance_path);
        fs::write(proof_path, &proof).unwrap();
    }

    debug_assert!({
        let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::new(proof.as_slice());
        VerificationStrategy::<_, V>::finalize(
            verify_proof::<_, V, _, _, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript_read,
            )
            .unwrap(),
        )
    });

    proof
}

/// Generates a native proof using original Plonk (GWC '19) multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Caches the instances and proof if `path = Some(instance_path, proof_path)` is specified.
pub fn gen_proof_gwc<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
    rng: &mut (impl Rng + Send),
    path: Option<(&Path, &Path)>,
) -> Vec<u8> {
    gen_proof::<C, ProverGWC<_>, VerifierGWC<_>>(params, pk, circuit, instances, rng, path)
}

/// Generates a native proof using SHPLONK multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Caches the instances and proof if `path` is specified.
pub fn gen_proof_shplonk<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
    rng: &mut (impl Rng + Send),
    path: Option<(&Path, &Path)>,
) -> Vec<u8> {
    gen_proof::<C, ProverSHPLONK<_>, VerifierSHPLONK<_>>(params, pk, circuit, instances, rng, path)
}

/// Generates a SNARK using either SHPLONK or GWC multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Tries to first deserialize from / later serialize the entire SNARK into `path` if specified.
/// Serialization is done using `bincode`.
pub fn gen_snark<'params, ConcreteCircuit, P, V>(
    params: &'params ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    rng: &mut (impl Rng + Send),
    path: Option<impl AsRef<Path>>,
) -> Snark
where
    ConcreteCircuit: CircuitExt<Fr>,
    P: Prover<'params, KZGCommitmentScheme<Bn256>>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    if let Some(path) = &path {
        if let Ok(snark) = read_snark(path) {
            return snark;
        }
    }
    let protocol = compile(
        params,
        pk.get_vk(),
        Config::kzg()
            .with_num_instance(circuit.num_instance())
            .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
    );

    let instances = circuit.instances();
    let proof =
        gen_proof::<ConcreteCircuit, P, V>(params, pk, circuit, instances.clone(), rng, None);

    let snark = Snark::new(protocol, instances, proof);
    if let Some(path) = &path {
        let f = File::create(path).unwrap();
        #[cfg(feature = "display")]
        let write_time = start_timer!(|| "Write SNARK");
        bincode::serialize_into(f, &snark).unwrap();
        #[cfg(feature = "display")]
        end_timer!(write_time);
    }
    snark
}

/// Generates a SNARK using GWC multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Tries to first deserialize from / later serialize the entire SNARK into `path` if specified.
/// Serialization is done using `bincode`.
pub fn gen_snark_gwc<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    rng: &mut (impl Rng + Send),
    path: Option<impl AsRef<Path>>,
) -> Snark {
    gen_snark::<ConcreteCircuit, ProverGWC<_>, VerifierGWC<_>>(params, pk, circuit, rng, path)
}

/// Generates a SNARK using SHPLONK multi-open scheme. Uses Poseidon for Fiat-Shamir.
///
/// Tries to first deserialize from / later serialize the entire SNARK into `path` if specified.
/// Serialization is done using `bincode`.
pub fn gen_snark_shplonk<ConcreteCircuit: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: ConcreteCircuit,
    rng: &mut (impl Rng + Send),
    path: Option<impl AsRef<Path>>,
) -> Snark {
    gen_snark::<ConcreteCircuit, ProverSHPLONK<_>, VerifierSHPLONK<_>>(
        params, pk, circuit, rng, path,
    )
}

/// Verifies a native proof using either SHPLONK or GWC proving method. Uses Poseidon for Fiat-Shamir.
///
pub fn verify_snark<'params, ConcreteCircuit, V>(
    verifier_params: &'params ParamsKZG<Bn256>,
    snark: Snark,
    vk: &VerifyingKey<G1Affine>,
) -> bool
where
    ConcreteCircuit: CircuitExt<Fr>,
    V: Verifier<
        'params,
        KZGCommitmentScheme<Bn256>,
        Guard = GuardKZG<'params, Bn256>,
        MSMAccumulator = DualMSM<'params, Bn256>,
    >,
{
    let mut transcript: PoseidonTranscript<_, _> =
        TranscriptReadBuffer::<_, G1Affine, _>::init(snark.proof.as_slice());
    let strategy = SingleStrategy::new(verifier_params);
    let instance_slice = snark.instances.iter().map(|x| &x[..]).collect::<Vec<_>>();
    match verify_proof::<_, V, _, _, _>(
        verifier_params,
        vk,
        strategy,
        &[instance_slice.as_slice()],
        &mut transcript,
    ) {
        Ok(_p) => true,
        Err(_e) => false,
    }
}

/// Verifies a native proof using SHPLONK proving method. Uses Poseidon for Fiat-Shamir.
///
pub fn verify_snark_shplonk<ConcreteCircuit>(
    verifier_params: &ParamsKZG<Bn256>,
    snark: Snark,
    vk: &VerifyingKey<G1Affine>,
) -> bool
where
    ConcreteCircuit: CircuitExt<Fr>,
{
    verify_snark::<ConcreteCircuit, VerifierSHPLONK<_>>(verifier_params, snark, vk)
}

/// Verifies a native proof using GWC proving method. Uses Poseidon for Fiat-Shamir.
///
pub fn verify_snark_gwc<ConcreteCircuit>(
    verifier_params: &ParamsKZG<Bn256>,
    snark: Snark,
    vk: &VerifyingKey<G1Affine>,
) -> bool
where
    ConcreteCircuit: CircuitExt<Fr>,
{
    verify_snark::<ConcreteCircuit, VerifierGWC<_>>(verifier_params, snark, vk)
}
