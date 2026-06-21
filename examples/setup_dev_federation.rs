//! End-to-end dev federation bootstrap.
//!
//! Reads `../asterism-core/.env` (where the dev secrets live), initializes
//! every SoftHSM token referenced by `HSM_DEV_{i}_LABEL`, derives a
//! `Pkcs11Signer` per `WALLET_TEST_{i}_MNEMONIC`, builds a
//! [`asterism_core::Federation`] at the configured derivation path, and
//! prints the descriptor.
//!
//! Run with:
//!
//! ```bash
//! cd asterism-dev-signer
//! cargo run --example setup_dev_federation
//! ```
//!
//! Required env (committed in `asterism-core/.env`):
//!
//! ```text
//! PKCS11_LIB=...libasterism_dev_hsm.so
//! SOFTHSM2_LIB=...libsofthsm2.so
//! HSM_DEV_1_LABEL=asterism-hsm-1
//! HSM_DEV_1_PIN=1111-1111
//! WALLET_TEST_1_MNEMONIC=abandon abandon ... about
//! # … through HSM_DEV_5_*, WALLET_TEST_5_MNEMONIC for a 3-of-5
//! WALLET_TEST_FEDERATION_PATH=m/48'/1'/0'/2'
//! WALLET_TEST_FEDERATION_THRESHOLD=3
//! ```

use std::str::FromStr;

use asterism_core::{Federation, NetworkType, Signer};
use asterism_dev_signer::{DevConfig, DevSetupError, init_dev_token, setup_dev_federation};
use bitcoin::bip32::DerivationPath;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    // Walk up from the example's CWD looking for `asterism-core/.env`.
    // Common dev pattern: run `cargo run --example ...` from this crate.
    for candidate in [
        "../asterism-core/.env",
        "../asterism/asterism-core/.env",
        ".env",
    ] {
        if dotenvy::from_filename(candidate).is_ok() {
            eprintln!("loaded env from {candidate}");
            break;
        }
    }

    let cfg = DevConfig::from_env()?;
    let path = std::env::var("WALLET_TEST_FEDERATION_PATH")
        .unwrap_or_else(|_| "m/48'/1'/0'/2'".to_string());
    let derivation_path = DerivationPath::from_str(&path)?;
    let threshold: u32 = std::env::var("WALLET_TEST_FEDERATION_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    // Step 1: ensure tokens exist.
    for i in 1..=16 {
        let label_var = format!("HSM_DEV_{i}_LABEL");
        let so_pin_var = format!("HSM_DEV_{i}_SO_PIN");
        let pin_var = format!("HSM_DEV_{i}_PIN");
        let label = match std::env::var(&label_var) {
            Ok(v) => v,
            Err(_) => break,
        };
        let so_pin = std::env::var(&so_pin_var).unwrap_or_else(|_| "0000".to_string());
        let pin = std::env::var(&pin_var)
            .map_err(|_| DevSetupError::Env(format!("{pin_var} not set")))?;
        match init_dev_token(&cfg, &label, &so_pin, &pin) {
            Ok(()) => eprintln!("token {label} ready"),
            Err(e) => eprintln!("warning: init_dev_token({label}) failed: {e}"),
        }
    }

    // Step 2: load all signers.
    let signers = setup_dev_federation(&cfg, &derivation_path)?;
    eprintln!("loaded {} signers at path {derivation_path}", signers.len());

    // Step 3: build a federation.
    let boxed: Vec<Box<dyn Signer>> = signers
        .into_iter()
        .map(|s| Box::new(s) as Box<dyn Signer>)
        .collect();
    let network = NetworkType::Bitcoin(bitcoin::Network::Testnet);
    let federation = Federation::new(threshold, boxed, network)?;

    // Step 4: emit the descriptor.
    println!("descriptor: {}", federation.descriptor_string());
    println!(
        "threshold: {}/{}",
        federation.threshold(),
        federation.signers().len()
    );

    Ok(())
}
