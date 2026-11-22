#!/usr/bin/env bash
# Builds the GitHub Pages site into web/dist. Needs the wasm32-unknown-unknown
# target and a wasm-bindgen CLI matching the version pinned in Cargo.toml.
#
#   web/build.sh && python3 -m http.server -d web/dist
set -euo pipefail
cd "$(dirname "$0")"

want=$(sed -n 's/^wasm-bindgen = "=\(.*\)"$/\1/p' Cargo.toml)
have=$(wasm-bindgen --version | cut -d' ' -f2)
if [ "$want" != "$have" ]; then
    echo "build.sh: Cargo.toml pins wasm-bindgen $want, but the CLI is $have" >&2
    echo "          cargo install wasm-bindgen-cli --version $want --locked" >&2
    exit 1
fi

cargo build --release --target wasm32-unknown-unknown

rm -rf dist
mkdir -p dist/wordlists
wasm-bindgen --target web --no-typescript \
    --remove-name-section --remove-producers-section \
    --out-dir dist/pkg target/wasm32-unknown-unknown/release/contaminate_web.wasm
cp static/* dist/

# The page fetches the bundled lists as plain text, and only on demand for
# lists that aren't compiled into the module (that is, `hashes`).
cp ../wordlists/*.txt dist/wordlists/
names=$(cd ../wordlists && ls *.txt | sed 's/\.txt$//; s/.*/"&"/' | paste -sd, -)
echo "[$names]" > dist/wordlists/index.json

echo "built $(du -sh dist | cut -f1) into web/dist"
