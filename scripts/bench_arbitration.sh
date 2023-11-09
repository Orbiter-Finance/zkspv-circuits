rm data/arbitration/*.snark
rm data/arbitration/*.yul
rm data/arbitration/*.calldata
rm data/arbitration/*.pk
rm cache_data/arbitration/*.snark
rm cache_data/arbitration/*.pk

rm arbitration_business
cargo clean
cargo build --release --bin arbitration_business
cp target/release/arbitration_business .
./arbitration_business