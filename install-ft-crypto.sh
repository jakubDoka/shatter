cargo install wasm-pack
(cd ft-crypto && $HOME/.cargo/bin/wasm-pack build --release --target web)
rm -rf assets/ft-crypto
mv ft-crypto/pkg assets/ft-crypto
rm assets/ft-crypto/.gitignore
