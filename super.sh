
export RUST_MIN_STACK=100000000
for c in evm state poseidon mpt super
do
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -F zkevm --release -- --nocapture test_${c}_circuit_verification 2>&1 | tee ${c}.log
done
