//! Place holders for CircuitExt Implementation of EVM circuits
//!
//! TODO: move those definitions to zkevm-circuit repo.

mod evm_circuit;
mod mpt_circuit;
mod poseidon_circuit;
mod state_circuit;
mod super_circuit;

#[cfg(all(test, feature = "zkevm"))]
mod test {
    use crate::{
        gen_pk,
        halo2::{gen_snark_shplonk, verify_snark_shplonk},
        CircuitExt,
    };
    use ark_std::test_rng;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{address, bytecode, geth_types::GethData, U256};
    use ethers_signers::{LocalWallet, Signer};
    use halo2_base::{halo2_proofs::halo2curves::bn256::Fr, utils::fs::gen_srs};
    use mock::{TestContext, MOCK_CHAIN_ID, MOCK_DIFFICULTY};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::{collections::HashMap, env};
    use zkevm_circuits::super_circuit::SuperCircuit;

    const TEST_CURRENT_K: u32 = 18;
    const TEST_MAX_CALLDATA: usize = 32;
    const TEST_MAX_INNER_BLOCKS: usize = 1;
    const TEST_MAX_TXS: usize = 1;
    const TEST_MOCK_RANDOMNESS: u64 = 0x100;

    #[test]
    fn test_evm_circuit_verification() {
        let circuit = super_circuit().evm_circuit;
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_mpt_circuit_verification() {
        let circuit = super_circuit().mpt_circuit;
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_poseidon_circuit_verification() {
        let circuit = super_circuit().poseidon_circuit;
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_state_circuit_verification() {
        let circuit = super_circuit().state_circuit;
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_super_circuit_verification() {
        let circuit = super_circuit();
        assert!(verify_circuit(circuit));
    }

    fn super_circuit() -> SuperCircuit<
        Fr,
        TEST_MAX_TXS,
        TEST_MAX_CALLDATA,
        TEST_MAX_INNER_BLOCKS,
        TEST_MOCK_RANDOMNESS,
    > {
        let block = block_1tx();
        let circuits_params = CircuitsParams {
            max_txs: TEST_MAX_TXS,
            max_calldata: TEST_MAX_CALLDATA,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            // TODO: fix after zkevm-circuits update.
            // max_evm_rows: 0,
            // max_keccak_rows: 0,
            keccak_padding: None,
            max_inner_blocks: TEST_MAX_INNER_BLOCKS,
        };
        let mut difficulty_be_bytes = [0u8; 32];
        let mut chain_id_be_bytes = [0u8; 32];
        MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
        MOCK_CHAIN_ID.to_big_endian(&mut chain_id_be_bytes);
        env::set_var("CHAIN_ID", hex::encode(chain_id_be_bytes));
        env::set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));

        SuperCircuit::<
            Fr,
            TEST_MAX_TXS,
            TEST_MAX_CALLDATA,
            TEST_MAX_INNER_BLOCKS,
            TEST_MOCK_RANDOMNESS,
        >::build(block, circuits_params)
        .unwrap()
        .1
    }

    fn block_1tx() -> GethData {
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            GAS
            STOP
        };

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

        let addr_a = wallet_a.address();
        let addr_b = address!("0x000000000000000000000000000000000000BBBB");

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let mut block: GethData = TestContext::<2, 1>::new(
            Some(vec![U256::zero()]),
            |accs| {
                accs[0].address(addr_b).balance(U256::from(1u64 << 20)).code(bytecode);
                accs[1].address(addr_a).balance(U256::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].from(accs[1].address).to(accs[0].address).gas(U256::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        block.sign(&wallets);
        block
    }

    fn verify_circuit<C: CircuitExt<Fr>>(circuit: C) -> bool {
        env::set_var("VERIFY_CONFIG", "./configs/verify_circuit.config");

        let mut rng = test_rng();
        let params = gen_srs(TEST_CURRENT_K);

        let pk = gen_pk(&params, &circuit, None);
        let vk = pk.get_vk();

        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        verify_snark_shplonk::<C>(&params, snark, vk)
    }
}
