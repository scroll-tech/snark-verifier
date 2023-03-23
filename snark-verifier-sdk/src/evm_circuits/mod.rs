//! Place holders for CircuitExt Implementation of EVM circuits
//!
//! TODO: move those definitions to zkevm-circuit repo.

#[cfg(test)]
mod evm_circuit;
#[cfg(test)]
mod mpt_circuit;
#[cfg(test)]
mod poseidon_circuit;
#[cfg(test)]
mod state_circuit;
#[cfg(test)]
mod super_circuit;

#[cfg(all(test, feature = "zkevm"))]
mod test {
    use crate::{
        evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
        gen_pk,
        halo2::{aggregation::AggregationCircuit, gen_snark_shplonk, verify_snark_shplonk},
        CircuitExt,
    };
    use ark_std::{end_timer, start_timer, test_rng};
    use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
    use eth_types::{address, bytecode, geth_types::GethData, U256};
    use ethers_signers::{LocalWallet, Signer};
    use halo2_base::{
        halo2_proofs::{halo2curves::bn256::Fr, plonk::Circuit},
        utils::fs::gen_srs,
    };
    use mock::{TestContext, MOCK_CHAIN_ID, MOCK_DIFFICULTY};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::{collections::HashMap, env};
    use zkevm_circuits::{
        evm_circuit::EvmCircuit,
        mpt_circuit::MptCircuit,
        poseidon_circuit::PoseidonCircuit,
        state_circuit::StateCircuit,
        super_circuit::SuperCircuit,
        util::{log2_ceil, SubCircuit},
        witness::block_convert,
    };

    const TEST_CURRENT_K: u32 = 19;
    const TEST_AGG_K: u32 = 24;
    const TEST_MAX_CALLDATA: usize = 3200;
    const TEST_MAX_INNER_BLOCKS: usize = 1;
    const TEST_MAX_TXS: usize = 1;
    const TEST_MOCK_RANDOMNESS: u64 = 0x100;

    #[test]
    fn test_evm_circuit_verification() {
        let circuit = build_circuit::<EvmCircuit<Fr>>();
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_mpt_circuit_verification() {
        let circuit = build_circuit::<MptCircuit<Fr>>();
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_poseidon_circuit_verification() {
        let circuit = build_circuit::<PoseidonCircuit<Fr>>();
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_state_circuit_verification() {
        let circuit = build_circuit::<StateCircuit<Fr>>();
        assert!(verify_circuit(circuit));
    }

    #[test]
    fn test_super_circuit_verification() {
        let circuit = build_circuit::<
            SuperCircuit<
                Fr,
                TEST_MAX_TXS,
                TEST_MAX_CALLDATA,
                TEST_MAX_INNER_BLOCKS,
                TEST_MOCK_RANDOMNESS,
            >,
        >();
        assert!(verify_circuit(circuit));
    }

    fn build_circuit<C: SubCircuit<Fr> + Circuit<Fr>>() -> C {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
        let geth_data = block_1tx();
        let circuits_params = CircuitsParams {
            max_txs: TEST_MAX_TXS,
            max_calldata: TEST_MAX_CALLDATA,
            max_rws: 200_000,
            max_copy_rows: 25600,
            max_exp_steps: 256,
            max_bytecode: 5120,
            // TODO: fix after zkevm-circuits update.
            // max_evm_rows: 0,
            // max_keccak_rows: 0,
            keccak_padding: Some(200_000),
            max_inner_blocks: TEST_MAX_INNER_BLOCKS,
        };
        let mut difficulty_be_bytes = [0u8; 32];
        let mut chain_id_be_bytes = [0u8; 32];
        MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
        MOCK_CHAIN_ID.to_big_endian(&mut chain_id_be_bytes);
        env::set_var("CHAIN_ID", hex::encode(chain_id_be_bytes));
        env::set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));

        let block_data =
            BlockData::new_from_geth_data_with_params(geth_data.clone(), circuits_params);
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
        block.evm_circuit_pad_to = circuits_params.max_rws;

        const NUM_BLINDING_ROWS: usize = 64;
        let (_, rows_needed) = C::min_num_rows_block(&block);
        let k = log2_ceil(NUM_BLINDING_ROWS + rows_needed);
        log::debug!("circuit needs k = {}", k);

        let circuit = C::new_from_block(&block);

        //let instance = circuit.instance();
        circuit
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
        std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");

        let mut rng = test_rng();
        let params = gen_srs(TEST_CURRENT_K);
        let params_outer = gen_srs(TEST_AGG_K);
        log::info!("finished parameter generation");

        let pk = gen_pk(&params, &circuit, None);
        let vk = pk.get_vk();
        log::info!("finished key extraction");

        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        log::info!("finished snark generation");

        if !verify_snark_shplonk::<C>(&params, snark.clone(), vk) {
            log::error!("snark verification failed");
            return false;
        }
        log::info!("snark verification succeeded");

        let agg_circuit = AggregationCircuit::new(&params_outer, [snark], &mut rng);
        let pk_outer = gen_pk(&params_outer, &agg_circuit, None);

        log::info!("finished aggregation circuit generation");

        let instances = agg_circuit.instances();
        let proof = gen_evm_proof_shplonk(
            &params_outer,
            &pk_outer,
            agg_circuit.clone(),
            instances.clone(),
            &mut rng,
        );

        log::info!("finished aggregation proof generation");

        let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
            &params_outer,
            pk_outer.get_vk(),
            agg_circuit.num_instance(),
            None,
        );
        log::info!("finished byte code generation");
        evm_verify(deployment_code, instances, proof);
        log::info!("EVM verification succeeded");
        true
    }

    #[test]
    fn super_circuit_two_layer_recursion() {
        let mut rng = test_rng();
        let params = gen_srs(TEST_CURRENT_K);
        let params_layer_1 = gen_srs(25);
        let params_layer_2 = gen_srs(25);
        log::info!("finished parameter generation");

        //
        // load circuit and generate first layer proof
        //
        let super_circuit_snark = {
            let circuit = build_circuit::<
                SuperCircuit<
                    Fr,
                    TEST_MAX_TXS,
                    TEST_MAX_CALLDATA,
                    TEST_MAX_INNER_BLOCKS,
                    TEST_MOCK_RANDOMNESS,
                >,
            >();
            log::info!("finished super circuit generation");

            let pk = gen_pk(&params, &circuit, None);
            let vk = pk.get_vk();
            log::info!("finished key extraction");
            log::info!("domain size {}", vk.get_domain().k());
            let super_circuit_timer = start_timer!(|| "super circuit snark gen");
            let super_circuit_snark =
                gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
            end_timer!(super_circuit_timer);

            let super_circuit_timer = start_timer!(|| "super circuit rust verify (optional)");
            if !verify_snark_shplonk::<
                SuperCircuit<
                    Fr,
                    TEST_MAX_TXS,
                    TEST_MAX_CALLDATA,
                    TEST_MAX_INNER_BLOCKS,
                    TEST_MOCK_RANDOMNESS,
                >,
            >(&params, super_circuit_snark.clone(), vk)
            {
                log::error!("super circuit snark verification failed");
                return;
            }
            log::info!("super circuit snark verification succeeded");
            end_timer!(super_circuit_timer);
            super_circuit_snark
        };
        //
        // build first layer recursion proof
        //
        std::env::set_var("VERIFY_CONFIG", "./configs/two_layer_recursion_first_layer.config");
        let layer_1_snark = {
            let agg_circuit =
                AggregationCircuit::new(&params_layer_1, [super_circuit_snark], &mut rng);
            let pk = gen_pk(&params_layer_1, &agg_circuit, None);
            let vk = pk.get_vk();
            log::info!("domain size {}", vk.get_domain().k());

            log::info!("finished layer 1 aggregation circuit generation");
            let layer_1_circuit_timer = start_timer!(|| "layer 1 circuit snark gen");
            let layer_1_snark = gen_snark_shplonk(
                &params_layer_1,
                &pk,
                agg_circuit.clone(),
                &mut rng,
                None::<String>,
            );
            end_timer!(layer_1_circuit_timer);

            let layer_1_circuit_timer = start_timer!(|| "layer 1 circuit rust verify (optional)");
            if !verify_snark_shplonk::<
                SuperCircuit<
                    Fr,
                    TEST_MAX_TXS,
                    TEST_MAX_CALLDATA,
                    TEST_MAX_INNER_BLOCKS,
                    TEST_MOCK_RANDOMNESS,
                >,
            >(&params_layer_1, layer_1_snark.clone(), vk)
            {
                log::error!("layer 1 snark verification failed");
                return;
            }
            log::info!("layer 1 snark verification succeeded");
            end_timer!(layer_1_circuit_timer);
            layer_1_snark
        };
        //
        // verify layer 1 snark with evm
        //
        {
            std::env::set_var("VERIFY_CONFIG", "./configs/two_layer_recursion_second_layer.config");
            
            let agg_circuit = AggregationCircuit::new(&params_layer_2, [layer_1_snark], &mut rng);
            let pk_outer = gen_pk(&params_layer_2, &agg_circuit, None);
            log::info!("finished layer 2 aggregation circuit generation");
            log::info!("domain size {}", pk_outer.get_vk().get_domain().k());

            let instances = agg_circuit.instances();
            let layer_2_circuit_timer = start_timer!(|| "layer 2 circuit snark gen");
            let proof = gen_evm_proof_shplonk(
                &params_layer_2,
                &pk_outer,
                agg_circuit.clone(),
                instances.clone(),
                &mut rng,
            );
            end_timer!(layer_2_circuit_timer);
            log::info!("finished layer 2 aggregation proof generation");

            let layer_2_circuit_timer = start_timer!(|| "layer 2 circuit evm verify");
            let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit>(
                &params_layer_2,
                pk_outer.get_vk(),
                agg_circuit.num_instance(),
                None,
            );
            log::info!("finished byte code generation");

            evm_verify(deployment_code, instances, proof);
            end_timer!(layer_2_circuit_timer);
            log::info!("EVM verification succeeded");
        }
    }
}
