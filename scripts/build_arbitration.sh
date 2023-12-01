#rm data/arbitration/*.snark
#rm data/arbitration/*.yul
#rm data/arbitration/*.calldata
#rm data/arbitration/*.pk
rm cache_data/arbitration/*.snark
#rm cache_data/arbitration/*.pk

rm arbitration_business
cargo clean
cargo run --release --bin arbitration_business