
export RUST_MIN_STACK=100000000
RUST_BACKTRACE=1 RUST_LOG=debug cargo test -F zkevm --release -- --nocapture test_super_circuit_verification 2>&1 | tee super.log
