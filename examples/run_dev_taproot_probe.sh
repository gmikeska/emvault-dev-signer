#!/usr/bin/env bash
# Self-contained runner for the dev-shim Taproot probe: spins up a throwaway
# SoftHSM token store + seed config, builds the shim + example, runs it, and
# cleans up. No pre-existing HSM state or root needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # emvault-dev-signer
SHIM_DIR="$HERE/../libemvault_dev_hsm"
SOFTHSM2_LIB="${SOFTHSM2_LIB:-/usr/lib/softhsm/libsofthsm2.so}"

# Build the shim (cdylib) + the example.
( cd "$SHIM_DIR" && cargo build --quiet )
SHIM_SO="$SHIM_DIR/target/debug/libemvault_dev_hsm.so"
( cd "$HERE" && cargo build --quiet --example dev_taproot_probe )

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/tokens"
cat > "$TMP/softhsm2.conf" <<EOF
directories.tokendir = $TMP/tokens
objectstore.backend = file
log.level = ERROR
EOF
cat > "$TMP/dev-hsm.toml" <<EOF
[[slots]]
label = "dev-tap-probe"
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
EOF

export SOFTHSM2_CONF="$TMP/softhsm2.conf"
export SOFTHSM2_LIB
export PKCS11_LIB="$SHIM_SO"
export DEV_HSM_CONFIG="$TMP/dev-hsm.toml"
export DEV_TAP_LABEL="dev-tap-probe"
export DEV_TAP_PIN="1234"
export DEV_TAP_SO_PIN="123456"

"$HERE/target/debug/examples/dev_taproot_probe"
