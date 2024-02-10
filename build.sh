sh ./install-htmx.sh
sh ./install-css.sh
sh ./install-script.sh
sh ./install-ft-crypto.sh

mkdir -p ./bin
cargo build --release --no-default-features
cp ./target/release/sem ./bin/sem

