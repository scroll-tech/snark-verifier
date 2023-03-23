cd snark-verifier-sdk
rm -rf data
mkdir data
cd ..

RUST_LOG=log MODE=greeter cargo test --release native::test_shplonk_zk_standard_plonk_rand -- --nocapture 2>&1 | tee logs/native_shplonk.log.greeter
RUST_LOG=log MODE=greeter cargo test --release evm::test_shplonk_zk_standard_plonk_rand -- --nocapture 2>&1 | tee logs/evm_shplonk.log.greeter
RUST_LOG=log MODE=greeter cargo test --release test_evm_verification -- --nocapture 2>&1 | tee logs/evm_verifier.log.greeter
RUST_LOG=log MODE=greeter cargo test --release test_aggregation_evm_verification -- --nocapture 2>&1 | tee logs/single_layer_aggregation.log.greeter
RUST_LOG=log MODE=greeter cargo test --release test_two_layer_aggregation_evm_verification -- --nocapture 2>&1 | tee logs/two_layer_aggregation.log.greeter
