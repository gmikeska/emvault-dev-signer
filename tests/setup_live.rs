//! Live-shim exercise of the [`setup`](emvault_dev_signer::setup) helpers:
//! [`DevConfig::from_env`], [`init_dev_token`], [`load_test_signer`], and
//! [`setup_dev_federation`].
//!
//! These need a real `libemvault_dev_hsm.so` behind a working SoftHSM, so —
//! exactly like `tests/mechanism_ids.rs` — every test runtime-skips (passing
//! trivially with an `eprintln!`) when `PKCS11_LIB` isn't set or the shim isn't
//! built. The token-touching tests additionally skip unless the dev token
//! `.env` (`HSM_DEV_{i}_LABEL` / `HSM_DEV_{i}_PIN`) is present, so a partial
//! environment never wedges the run.
//!
//! To run for real:
//!
//! ```bash
//! cd ../libemvault_dev_hsm && cargo build --release
//! cd ../emvault-dev-signer
//! # PKCS11_LIB, SOFTHSM2_LIB, HSM_DEV_*_LABEL/PIN, DEV_HSM_SLOT_*_MNEMONIC
//! # all live in ../emvault-core/.env (loaded automatically below).
//! cargo test --test setup_live -- --nocapture
//! ```

use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use emvault_core::Signer;
use emvault_dev_signer::{DevConfig, init_dev_token, load_test_signer, setup_dev_federation};

/// Default derivation path when `WALLET_TEST_FEDERATION_PATH` is unset — matches
/// the example bootstrap and the SoftHSM integration suite.
const DEFAULT_PATH: &str = "m/48'/1'/0'/2'";

/// Load the shared dev `.env` (best-effort; harmless if absent) and return the
/// shim path only when `PKCS11_LIB` is set **and** the file exists. `None` →
/// caller skips. Mirrors `mechanism_ids.rs::pkcs11_lib_path` + its existence
/// check, folded together.
fn shim_path() -> Option<String> {
    let _ = dotenvy::from_filename("../emvault-core/.env");
    let path = std::env::var("PKCS11_LIB").ok()?;
    if std::path::Path::new(&path).exists() {
        Some(path)
    } else {
        eprintln!("PKCS11_LIB={path} does not exist; skipping.");
        None
    }
}

/// The configured derivation path, or [`DEFAULT_PATH`].
fn federation_path() -> DerivationPath {
    let raw =
        std::env::var("WALLET_TEST_FEDERATION_PATH").unwrap_or_else(|_| DEFAULT_PATH.to_string());
    DerivationPath::from_str(&raw).expect("WALLET_TEST_FEDERATION_PATH is a valid derivation path")
}

/// `DevConfig::from_env` reflects `PKCS11_LIB` and validates the path exists.
#[test]
fn dev_config_from_env_reflects_shim_path() {
    let Some(path) = shim_path() else {
        eprintln!("PKCS11_LIB not set; skipping dev_config_from_env_reflects_shim_path.");
        return;
    };

    let cfg = DevConfig::from_env().expect("DevConfig::from_env with a valid PKCS11_LIB");
    assert!(
        cfg.shim_library_path.exists(),
        "from_env only returns Ok when the shim path exists"
    );
    assert_eq!(
        cfg.shim_library_path,
        std::path::PathBuf::from(&path),
        "shim_library_path is exactly PKCS11_LIB"
    );
}

/// End-to-end single-signer path: initialize (or reuse) the first dev token,
/// then derive a signer and assert its BIP-32 invariants line up.
#[test]
fn init_token_and_load_signer() {
    let Some(_path) = shim_path() else {
        eprintln!("PKCS11_LIB not set; skipping init_token_and_load_signer.");
        return;
    };
    let (Ok(label), Ok(pin)) = (
        std::env::var("HSM_DEV_1_LABEL"),
        std::env::var("HSM_DEV_1_PIN"),
    ) else {
        eprintln!("HSM_DEV_1_LABEL/PIN unset; skipping init_token_and_load_signer.");
        return;
    };

    let cfg = DevConfig::from_env().expect("DevConfig::from_env");
    let so_pin = std::env::var("HSM_DEV_1_SO_PIN").unwrap_or_else(|_| "0000".to_string());

    // Idempotent: a no-op when the token already exists, a real init otherwise.
    init_dev_token(&cfg, &label, &so_pin, &pin).expect("init_dev_token (idempotent)");

    let path = federation_path();
    let signer = load_test_signer(&cfg, &label, &pin, &path).expect("load_test_signer");

    // Basic invariants the derive path must uphold.
    assert_eq!(
        signer.derivation_path(),
        &path,
        "signer derives at the requested path"
    );
    assert_eq!(
        signer.fingerprint(),
        signer.xpub().fingerprint(),
        "reported fingerprint matches its own xpub"
    );
    assert!(
        !signer.descriptor_key().to_string().is_empty(),
        "signer contributes a non-empty descriptor key"
    );
    assert!(
        !signer.supported_networks().is_empty(),
        "signer advertises at least one supported network"
    );
}

/// Federation bootstrap: with two or more `HSM_DEV_*` tokens configured,
/// `setup_dev_federation` loads a signer per token, all at the shared path.
#[test]
fn setup_dev_federation_loads_all_signers() {
    let Some(_path) = shim_path() else {
        eprintln!("PKCS11_LIB not set; skipping setup_dev_federation_loads_all_signers.");
        return;
    };
    // Needs at least a 2-of-N: both HSM_DEV_1 and HSM_DEV_2 must be present.
    if std::env::var("HSM_DEV_1_LABEL").is_err() || std::env::var("HSM_DEV_2_LABEL").is_err() {
        eprintln!(
            "fewer than two HSM_DEV_*_LABEL entries; skipping setup_dev_federation_loads_all_signers."
        );
        return;
    }

    let cfg = DevConfig::from_env().expect("DevConfig::from_env");

    // Ensure every configured token exists first (idempotent), so the load can't
    // fail on a fresh checkout that hasn't been bootstrapped yet.
    for i in 1..=16 {
        let Ok(label) = std::env::var(format!("HSM_DEV_{i}_LABEL")) else {
            break;
        };
        let Ok(pin) = std::env::var(format!("HSM_DEV_{i}_PIN")) else {
            break;
        };
        let so_pin = std::env::var(format!("HSM_DEV_{i}_SO_PIN")).unwrap_or_else(|_| "0000".into());
        init_dev_token(&cfg, &label, &so_pin, &pin).expect("init_dev_token (idempotent)");
    }

    let path = federation_path();
    let signers = setup_dev_federation(&cfg, &path).expect("setup_dev_federation");

    assert!(
        signers.len() >= 2,
        "a valid federation needs at least two signers, got {}",
        signers.len()
    );
    for signer in &signers {
        assert_eq!(
            signer.derivation_path(),
            &path,
            "every federation member derives at the shared path"
        );
    }
}
