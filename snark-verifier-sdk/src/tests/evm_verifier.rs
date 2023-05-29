use super::TestCircuit1;
use crate::{
    evm_api::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier},
    halo2_api::gen_pk,
    CircuitExt,
};
use ark_std::test_rng;
use halo2_base::halo2_proofs;
use halo2_proofs::halo2curves::bn256::Bn256;
use snark_verifier::{
    loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs,
    pcs::kzg::{Bdfg21, Kzg},
};

#[test]
fn test_evm_verification() {
    std::env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");

    let mut rng = test_rng();
    let params = gen_srs(8);

    let circuit = TestCircuit1::rand(&mut rng);
    let pk = gen_pk(&params, &circuit, None);
    let deployment_code = gen_evm_verifier::<TestCircuit1, Kzg<Bn256, Bdfg21>>(
        &params,
        pk.get_vk(),
        circuit.num_instance(),
        None,
    );

    let instances = circuit.instances();
    let proof = gen_evm_proof_shplonk(&params, &pk, circuit.clone(), instances.clone(), &mut rng);
    evm_verify(deployment_code.clone(), circuit.instances(), proof)
}
