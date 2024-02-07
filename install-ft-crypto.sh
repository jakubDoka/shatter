(cd ft-crypto && wasm-pack build --target web)
rm -rf assets/ft-crypto
mv ft-crypto/pkg assets/ft-crypto
rm assets/ft-crypto/.gitignore
