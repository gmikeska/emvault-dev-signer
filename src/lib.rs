//! # asterism-dev-signer
//!
//! Dev/CI [`HsmBackend`](asterism_pkcs11::HsmBackend) implementation for
//! the [`libasterism_dev_hsm.so`] PKCS#11 shim, plus the small amount of
//! tooling (BIP-39 → seed conversion, programmatic token init,
//! federation bootstrap) that turns a fresh checkout into a working
//! 3-of-5 signer set.
//!
//! `asterism-dev-signer` is **separate from `asterism`** on purpose. By
//! living outside the production crate graph, it cannot accidentally
//! end up in a release build of any consumer; web apps that ship to
//! production keep `asterism-dev-signer` strictly under
//! `[dev-dependencies]`.
//!
//! [`libasterism_dev_hsm.so`]: ../libasterism_dev_hsm/
//!
//! ## Where mnemonics live
//!
//! `asterism-dev-signer` is **mnemonic-free** by design. All BIP-39
//! handling — mnemonic parsing, PBKDF2 stretching, slot/label →
//! seed bookkeeping — lives in `libasterism_dev_hsm.so` itself. The
//! shim reads `DEV_HSM_SLOT_{i}_MNEMONIC` env vars or a TOML config at
//! `$DEV_HSM_CONFIG` and applies the right seed when
//! `C_DeriveKey(CKM_DEV_BIP32_MASTER_DERIVE)` runs. From this crate's
//! perspective, derivation is just a PKCS#11 call — same as it would
//! be against a Utimaco or Thales HSM. See
//! `libasterism_dev_hsm/README.md` for the seed-config schema.
//!
//! ## Layout
//!
//! - [`backend`] — the [`DevBackend`] struct and the `CKM_DEV_BIP32_*`
//!   / `CKA_DEV_BIP32_*` constants. These are mirrored in
//!   `libasterism_dev_hsm/src/constants.rs`; the
//!   `tests/mechanism_ids.rs` integration test loads the shim and
//!   verifies they agree at CI time.
//! - [`setup`] — [`DevConfig`], [`init_dev_token`],
//!   [`load_test_signer`], and [`setup_dev_federation`].
//! - [`error`] — [`DevSetupError`].
//!
//! ## A 6-line dev federation
//!
//! ```rust,ignore
//! use asterism_dev_signer::{DevConfig, setup_dev_federation};
//! use bitcoin::bip32::DerivationPath;
//! use std::str::FromStr;
//!
//! dotenvy::from_filename("../asterism/asterism-core/.env").ok();
//! let cfg = DevConfig::from_env()?;
//! let path = DerivationPath::from_str("m/48'/1'/0'/2'")?;
//! let signers = setup_dev_federation(&cfg, &path)?;
//! println!("loaded {} dev signers", signers.len());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]

pub mod backend;
pub mod error;
pub mod setup;

pub use asterism_pkcs11;

pub use backend::{
    CKA_DEV_BIP32_CHAIN_CODE, CKA_DEV_BIP32_CHILD_DEPTH, CKA_DEV_BIP32_CHILD_INDEX,
    CKA_DEV_BIP32_PARENT_FINGERPRINT, CKM_DEV_BIP32_CHILD_DERIVE, CKM_DEV_BIP32_MASTER_DERIVE,
    DevBackend,
};
pub use error::DevSetupError;
pub use setup::{DevConfig, init_dev_token, load_test_signer, setup_dev_federation};
