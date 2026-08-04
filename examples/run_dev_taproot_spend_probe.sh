#!/usr/bin/env bash
# Self-contained runner for the dev-shim Taproot SPEND probe: spins up a
# throwaway SoftHSM store with three seeded slots, builds the shim + example,
# runs a full 2-of-3 tr(NUMS,multi_a) script-path spend, and cleans up.
# No pre-existing HSM state or root needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # emvault-dev-signer
SHIM_DIR="$HERE/../libemvault_dev_hsm"
SOFTHSM2_LIB="${SOFTHSM2_LIB:-/usr/lib/softhsm/libsofthsm2.so}"

# Build the shim (cdylib) + the example.
( cd "$SHIM_DIR" && cargo build --quiet )
SHIM_SO="$SHIM_DIR/target/debug/libemvault_dev_hsm.so"
( cd "$HERE" && cargo build --quiet --example dev_taproot_spend_probe )

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/tokens"
cat > "$TMP/softhsm2.conf" <<EOF
directories.tokendir = $TMP/tokens
objectstore.backend = file
log.level = ERROR
EOF

# Three slots, three distinct BIP-39 seeds (standard test vectors) so the
# three cosigners hold independent keys.
cat > "$TMP/dev-hsm.toml" <<EOF
[[slots]]
label = "dev-tap-a"
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

[[slots]]
label = "dev-tap-b"
mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"

[[slots]]
label = "dev-tap-c"
mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
EOF

export SOFTHSM2_CONF="$TMP/softhsm2.conf"
export SOFTHSM2_LIB
export PKCS11_LIB="$SHIM_SO"
export DEV_HSM_CONFIG="$TMP/dev-hsm.toml"
export DEV_TAP_LABELS="dev-tap-a,dev-tap-b,dev-tap-c"
export DEV_TAP_PIN="1234"
export DEV_TAP_SO_PIN="123456"

"$HERE/target/debug/examples/dev_taproot_spend_probe"
