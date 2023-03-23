
export RUST_MIN_STACK=100000000
for c in evm state poseidon mpt super
do
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -F zkevm --release -- --nocapture test_${c}_circuit_verification 2>&1 | tee ${c}.log
done

RUST_BACKTRACE=1 RUST_LOG=debug cargo test -F zkevm --release -- --nocapture super_circuit_two_layer_recursion 2>&1 | tee super_2_layers.log