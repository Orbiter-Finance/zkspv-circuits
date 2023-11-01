rm data/arbitration/*.snark
rm data/arbitration/*.yul
rm data/arbitration/*.calldata

rm services
rm services.log
cargo clean
cargo build --release --bin services
cp target/release/services .
./services