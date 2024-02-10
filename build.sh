sh ./install-htmx.sh
sh ./install-css.sh
sh ./install-script.sh
sh ./install-ft-crypto.sh

cargo build --release --no-default-features --target x86_64-unknown-linux-musl
