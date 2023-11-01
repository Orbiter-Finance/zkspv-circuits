rm data/arbitration/*.snark
rm data/arbitration/*.yul
rm data/arbitration/*.calldata

rm arbitration_business
rm arbitration_business.log
cargo clean
cargo build --release --bin arbitration_business
cp target/release/arbitration_business .
./arbitration_business