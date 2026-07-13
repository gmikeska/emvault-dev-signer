# emvault-dev-signer

> Dev/CI [`HsmBackend`](https://github.com/gmikeska/emvault-pkcs11)
> implementation for
> [`libemvault_dev_hsm.so`](https://github.com/gmikeska/libemvault_dev_hsm),
> plus the small amount of tooling that turns a fresh checkout into a working
> 3-of-5 signer set.

> ⚠️ **Dev/CI only — never ship this in production.** It drives a SoftHSM 2 +
> software-BIP-32 setup and deals in plaintext seeds and default PINs behind
> the PKCS#11 shim. Keep it in `[dev-dependencies]` only; it must never land in
> a release binary.

## Why this crate exists

`emvault-pkcs11` ships the `HsmBackend` trait plus production
implementations (`UtimacoBackend`, `ThalesBackend`) that map vendor
PKCS#11 mechanism IDs onto BIP-32 master/child derivation. To run
identically against a SoftHSM 2 development setup, we'd need a "vendor"
that means "software BIP-32 + SoftHSM 2."

That vendor is the
[`libemvault_dev_hsm.so`](https://github.com/gmikeska/libemvault_dev_hsm)
shim. The matching `HsmBackend` impl is `DevBackend` in this crate.

By keeping `DevBackend` in a **separate crate** outside the production
graph, web apps can safely reference EmVault in `[dependencies]` and
this crate only in `[dev-dependencies]`. There is no dev-only path
inside `emvault-pkcs11` that could leak into a release binary.

```
                  emvault-pkcs11
                  ┌─────────────────────────────────────────────┐
                  │  HsmBackend trait                           │
                  │  Pkcs11Signer                               │
                  │  UtimacoBackend  (for Utimaco .so)          │
                  │  ThalesBackend   (for Thales .so)           │
                  └──────────────────────────┬──────────────────┘
                                             │
                                             │ depends on (for the trait)
                                             │
                  emvault-dev-signer         │
                  ┌──────────────────────────┴──────────────────┐
                  │  DevBackend      (for libemvault_dev_hsm)  │
                  │  DevConfig       (SoftHSM paths, token init)│
                  │  setup_dev_federation()                     │
                  └──────────────────────────┬──────────────────┘
                                             │
                                             │ points library_path at
                                             ▼
                  libemvault_dev_hsm
                  ┌─────────────────────────────────────────────┐
                  │  PKCS#11 shim .so (SoftHSM + sw BIP-32)     │
                  └─────────────────────────────────────────────┘
```

## Crate Cargo deps

```toml
[dependencies]
emvault-pkcs11 = { version = "0.3.0", path = "../emvault-pkcs11" }
emvault-core   = { version = "0.3.0", path = "../emvault-core" }
bitcoin = "0.32.10"
cryptoki = "0.12"
hex = "0.4"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
dotenvy = "0.15"
log = "0.4"
```

This crate is **mnemonic-free** — there's no `bip39` or `secrecy`
dependency. See "Where do mnemonics come from?" below.

## Modules

| Module    | What it is                                                                |
| --------- | ------------------------------------------------------------------------- |
| `backend` | `DevBackend` and the `CKM_DEV_BIP32_*` / `CKA_DEV_BIP32_*` constants      |
| `setup`   | `DevConfig`, `init_dev_token`, `load_test_signer`, `setup_dev_federation` |
| `error`   | `DevSetupError`                                                           |

## Where do mnemonics come from?

They live in [`libemvault_dev_hsm`](https://github.com/gmikeska/libemvault_dev_hsm).
The shim reads `DEV_HSM_SLOT_{i}_MNEMONIC` env vars (or a TOML at
`$DEV_HSM_CONFIG`) and converts them to seeds inside the `.so`. EmVault
never sees a mnemonic and never feeds seed material across the PKCS#11
ABI — the empty `&[]` seed passed to `derive_from_seed` tells the shim
"use whatever seed you have configured for this session's slot."

This keeps **all** dev-only "cheating" — software BIP-32, BIP-39
PBKDF2, plaintext seeds in process memory — strictly behind the
PKCS#11 ABI boundary, where it can't accidentally leak into a release
binary that pulls in `emvault-pkcs11`.

## Bootstrap

```bash
# 1. Build the shim (separate crate, separate target dir):
cd ../libemvault_dev_hsm && cargo build --release
# → ../libemvault_dev_hsm/target/release/libemvault_dev_hsm.so

# 2. Configure .env (committed at ../emvault-core/.env):
PKCS11_LIB=/abs/path/to/libemvault_dev_hsm.so
SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so          # read by the shim
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf              # read by the shim

HSM_DEV_1_LABEL=emvault-hsm-1
HSM_DEV_1_PIN=1111-1111
DEV_HSM_SLOT_0_MNEMONIC="abandon abandon abandon ... about"  # read by the shim

# … continue for HSM_DEV_2..N, DEV_HSM_SLOT_{1..N-1}_MNEMONIC

# 3. Initialize tokens (one-shot, idempotent):
cargo run --example setup_dev_federation

# 4. Use the federation in tests:
#    let cfg = DevConfig::from_env()?;
#    let signers = setup_dev_federation(&cfg, &path)?;
```

## A 6-line dev federation

```rust,ignore
use emvault_dev_signer::{DevConfig, setup_dev_federation};
use bitcoin::bip32::DerivationPath;
use std::str::FromStr;

dotenvy::from_filename("../emvault-core/.env").ok();
let cfg = DevConfig::from_env()?;
let path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
let signers = setup_dev_federation(&cfg, &path)?;
println!("loaded {} dev signers", signers.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Mechanism / attribute IDs

These are the dev shim's own vendor-defined IDs. They are mirrored in
`libemvault_dev_hsm/src/constants.rs`; the
`tests/mechanism_ids.rs` integration test loads the shim and verifies
they agree at CI time.

| Constant                          | Value         |
| --------------------------------- | ------------- |
| `CKM_DEV_BIP32_MASTER_DERIVE`     | `0x8000_D001` |
| `CKM_DEV_BIP32_CHILD_DERIVE`      | `0x8000_D002` |
| `CKA_DEV_BIP32_CHAIN_CODE`        | `0x8000_D101` |
| `CKA_DEV_BIP32_CHILD_DEPTH`       | `0x8000_D102` |
| `CKA_DEV_BIP32_PARENT_FINGERPRINT`| `0x8000_D103` |
| `CKA_DEV_BIP32_CHILD_INDEX`       | `0x8000_D104` |

## License

MIT OR Apache-2.0
