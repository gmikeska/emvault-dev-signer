# asterism-dev-signer

> Dev/CI [`HsmBackend`](../asterism-pkcs11/src/backend/mod.rs) implementation
> for [`libasterism_dev_hsm.so`](../libasterism_dev_hsm/), plus the small
> amount of tooling that turns a fresh checkout into a working 3-of-5
> signer set.

## Why this crate exists

`asterism-pkcs11` ships the `HsmBackend` trait plus production
implementations (`UtimacoBackend`, `ThalesBackend`) that map vendor
PKCS#11 mechanism IDs onto BIP-32 master/child derivation. To run
identically against a SoftHSM 2 development setup, we'd need a "vendor"
that means "software BIP-32 + SoftHSM 2."

That vendor is the [`libasterism_dev_hsm.so`](../libasterism_dev_hsm/)
shim. The matching `HsmBackend` impl is `DevBackend` in this crate.

By keeping `DevBackend` in a **separate crate** outside the production
graph, web apps can safely reference Asterism in `[dependencies]` and
this crate only in `[dev-dependencies]`. There is no dev-only path
inside `asterism-pkcs11` that could leak into a release binary.

```
                  asterism-pkcs11
                  ┌─────────────────────────────────────────────┐
                  │  HsmBackend trait                           │
                  │  Pkcs11Signer                               │
                  │  UtimacoBackend  (for Utimaco .so)          │
                  │  ThalesBackend   (for Thales .so)           │
                  └──────────────────────────┬──────────────────┘
                                             │
                                             │ depends on (for the trait)
                                             │
                  asterism-dev-signer         │
                  ┌──────────────────────────┴──────────────────┐
                  │  DevBackend      (for libasterism_dev_hsm)  │
                  │  DevConfig       (SoftHSM paths, token init)│
                  │  setup_dev_federation()                     │
                  └──────────────────────────┬──────────────────┘
                                             │
                                             │ points library_path at
                                             ▼
                  libasterism_dev_hsm
                  ┌─────────────────────────────────────────────┐
                  │  PKCS#11 shim .so (SoftHSM + sw BIP-32)     │
                  └─────────────────────────────────────────────┘
```

## Crate Cargo deps

```toml
[dependencies]
asterism-pkcs11 = { path = "../asterism-pkcs11" }
asterism-core   = { path = "../asterism-core" }
bitcoin = "0.32.10"
cryptoki = "0.12"
thiserror = "2"
dotenvy = "0.15"
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

They live in [`libasterism_dev_hsm`](../libasterism_dev_hsm/README.md).
The shim reads `DEV_HSM_SLOT_{i}_MNEMONIC` env vars (or a TOML at
`$DEV_HSM_CONFIG`) and converts them to seeds inside the `.so`. Asterism
never sees a mnemonic and never feeds seed material across the PKCS#11
ABI — the empty `&[]` seed passed to `derive_from_seed` tells the shim
"use whatever seed you have configured for this session's slot."

This keeps **all** dev-only "cheating" — software BIP-32, BIP-39
PBKDF2, plaintext seeds in process memory — strictly behind the
PKCS#11 ABI boundary, where it can't accidentally leak into a release
binary that pulls in `asterism-pkcs11`.

## Bootstrap

```bash
# 1. Build the shim (separate crate, separate target dir):
cd ../libasterism_dev_hsm && cargo build --release
# → ../libasterism_dev_hsm/target/release/libasterism_dev_hsm.so

# 2. Configure .env (committed at ../asterism-core/.env):
PKCS11_LIB=/abs/path/to/libasterism_dev_hsm.so
SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so          # read by the shim
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf              # read by the shim

HSM_DEV_1_LABEL=asterism-hsm-1
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
use asterism_dev_signer::{DevConfig, setup_dev_federation};
use bitcoin::bip32::DerivationPath;
use std::str::FromStr;

dotenvy::from_filename("../asterism/asterism-core/.env").ok();
let cfg = DevConfig::from_env()?;
let path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
let signers = setup_dev_federation(&cfg, &path)?;
println!("loaded {} dev signers", signers.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Mechanism / attribute IDs

These are the dev shim's own vendor-defined IDs. They are mirrored in
`libasterism_dev_hsm/src/constants.rs`; the
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
