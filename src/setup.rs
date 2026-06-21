//! Dev/CI tooling for getting `Pkcs11Signer`s wired up against the
//! `libasterism_dev_hsm.so` shim with as little ceremony as possible.
//!
//! The three entry points are:
//!
//! - [`init_dev_token`] — programmatic `pkcs11-tool --init-token`
//!   equivalent, so tests can reset their tokens without shelling out.
//! - [`load_test_signer`] — opens a session, converts a BIP-39 mnemonic
//!   to a 64-byte seed, and calls
//!   [`asterism_pkcs11::Pkcs11Signer::derive_from_seed`].
//! - [`setup_dev_federation`] — reads the `WALLET_TEST_*_MNEMONIC`,
//!   `HSM_DEV_*_LABEL`, and `HSM_DEV_*_PIN` triples out of `.env` and
//!   produces a vec of fully-configured `Pkcs11Signer`s.

use std::path::{Path, PathBuf};

use asterism_pkcs11::Pkcs11Signer;
use asterism_pkcs11::config::SlotIdentifier;
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use secrecy::ExposeSecret;

use crate::backend::DevBackend;
use crate::error::DevSetupError;
use crate::seed::mnemonic_to_seed_no_passphrase;

/// Default network for dev signers — testnet matches the SoftHSM-backed
/// integration test suite.
const DEFAULT_NETWORK: Network = Network::Testnet;

/// Configuration for the dev HSM environment.
#[derive(Clone, Debug)]
pub struct DevConfig {
    /// Path to `libasterism_dev_hsm.so`.
    pub shim_library_path: PathBuf,
    /// Path to `libsofthsm2.so` (the shim reads this through
    /// `$SOFTHSM2_LIB`).
    pub softhsm_library_path: PathBuf,
    /// Path to `softhsm2.conf` (the shim inherits this through
    /// `$SOFTHSM2_CONF`).
    pub softhsm_conf_path: PathBuf,
}

impl DevConfig {
    /// Read paths from environment variables. Honors `PKCS11_LIB`
    /// (preferred) and `SOFTHSM2_LIB` / `SOFTHSM2_CONF`.
    ///
    /// # Errors
    ///
    /// Returns [`DevSetupError::Env`] if any required variable is
    /// missing, or [`DevSetupError::Path`] if a configured path doesn't
    /// exist.
    pub fn from_env() -> Result<Self, DevSetupError> {
        let shim = std::env::var("PKCS11_LIB")
            .map_err(|_| DevSetupError::Env("PKCS11_LIB not set".into()))?;
        let softhsm = std::env::var("SOFTHSM2_LIB")
            .map_err(|_| DevSetupError::Env("SOFTHSM2_LIB not set".into()))?;
        let conf = std::env::var("SOFTHSM2_CONF").unwrap_or_else(|_| {
            // `softhsm2.conf` is optional from SoftHSM's POV (it
            // searches default locations), but we still default to the
            // canonical path so logs / dotenvy are explicit.
            "/etc/softhsm/softhsm2.conf".to_string()
        });

        let cfg = Self {
            shim_library_path: PathBuf::from(shim),
            softhsm_library_path: PathBuf::from(softhsm),
            softhsm_conf_path: PathBuf::from(conf),
        };
        cfg.check_paths()?;
        Ok(cfg)
    }

    fn check_paths(&self) -> Result<(), DevSetupError> {
        require_path(&self.shim_library_path, "shim_library_path")?;
        require_path(&self.softhsm_library_path, "softhsm_library_path")?;
        // `softhsm_conf_path` is allowed to be missing — SoftHSM will
        // search default locations.
        Ok(())
    }
}

fn require_path(p: &Path, what: &str) -> Result<(), DevSetupError> {
    if !p.exists() {
        return Err(DevSetupError::Path(format!(
            "{what} {p:?} does not exist"
        )));
    }
    Ok(())
}

/// Initialize a SoftHSM token for development use.
///
/// Programmatic equivalent of `pkcs11-tool --init-token`: opens the
/// shim, finds an uninitialized slot, calls `C_InitToken`, then opens a
/// session as SO and runs `C_InitPIN` to set the user PIN.
///
/// If a token with `label` already exists this is a no-op.
///
/// # Errors
///
/// Returns [`DevSetupError`] for any cryptoki/HSM-level failure or if
/// no uninitialized slot is available.
pub fn init_dev_token(
    config: &DevConfig,
    label: &str,
    so_pin: &str,
    user_pin: &str,
) -> Result<(), DevSetupError> {
    let pkcs11 = Pkcs11::new(&config.shim_library_path)?;
    pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;

    // Already initialized? Then we're done.
    for slot in pkcs11.get_slots_with_initialized_token()? {
        if let Ok(info) = pkcs11.get_token_info(slot)
            && info.label().trim() == label
        {
            log::info!("token {label:?} already initialized");
            return Ok(());
        }
    }

    let slot = pkcs11
        .get_all_slots()?
        .into_iter()
        .find(|s| {
            !pkcs11
                .get_slots_with_initialized_token()
                .map(|init| init.contains(s))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            DevSetupError::Env("no uninitialized SoftHSM slot available".into())
        })?;

    let so_pin_auth = AuthPin::new(so_pin.into());
    pkcs11.init_token(slot, &so_pin_auth, label)?;

    let session = pkcs11.open_rw_session(slot)?;
    session.login(UserType::So, Some(&so_pin_auth))?;
    let user_pin_auth = AuthPin::new(user_pin.into());
    session.init_pin(&user_pin_auth)?;
    session.logout()?;
    drop(session);

    Ok(())
}

/// Open a session, derive a signer from a BIP-39 mnemonic, and return
/// it ready for federation construction.
///
/// This is the dev equivalent of a key ceremony: in production, the
/// ceremony is a formal process involving multiple HSMs, key
/// custodians, and ceremony scripts. Here we collapse it to one call.
///
/// # Errors
///
/// Returns [`DevSetupError`] for invalid mnemonics, missing tokens, or
/// any HSM-level failure.
pub fn load_test_signer(
    config: &DevConfig,
    token_label: &str,
    pin: &str,
    mnemonic: &str,
    derivation_path: &DerivationPath,
) -> Result<Pkcs11Signer, DevSetupError> {
    let seed = mnemonic_to_seed_no_passphrase(mnemonic)?;

    let pkcs11_cfg = asterism_pkcs11::Pkcs11Config::new(
        &config.shim_library_path,
        SlotIdentifier::label(token_label),
        pin.to_string(),
        derivation_path.clone(),
        Box::new(DevBackend),
    );
    let session = asterism_pkcs11::Pkcs11Session::open(
        &pkcs11_cfg,
        &SlotIdentifier::label(token_label),
        pin,
    )?;

    let signer = Pkcs11Signer::derive_from_seed(
        session,
        token_label,
        derivation_path,
        DEFAULT_NETWORK,
        Box::new(DevBackend),
        seed.expose_secret().as_slice(),
    )?;
    Ok(signer)
}

/// Set up a complete dev federation from `.env`.
///
/// Reads tuples of `WALLET_TEST_{i}_MNEMONIC`, `HSM_DEV_{i}_LABEL`, and
/// `HSM_DEV_{i}_PIN` for `i` from 1 upwards (stopping at the first gap)
/// and returns a vec of `Pkcs11Signer`s ready to wrap into a
/// [`asterism_core::Federation`].
///
/// `derivation_path` is shared across all signers — every member of a
/// federation derives at the same path (e.g. `m/48'/1'/0'/2'`).
///
/// Returns [`DevSetupError::Federation`] if fewer than 2 signers can be
/// loaded (a valid federation needs at least 2-of-N).
///
/// # Errors
///
/// Returns [`DevSetupError`] for any HSM, env, or signer-construction
/// failure.
pub fn setup_dev_federation(
    config: &DevConfig,
    derivation_path: &DerivationPath,
) -> Result<Vec<Pkcs11Signer>, DevSetupError> {
    let mut signers = Vec::new();
    for i in 1..=16 {
        let mnemonic_var = format!("WALLET_TEST_{i}_MNEMONIC");
        let label_var = format!("HSM_DEV_{i}_LABEL");
        let pin_var = format!("HSM_DEV_{i}_PIN");

        let mnemonic = match std::env::var(&mnemonic_var) {
            Ok(v) => v,
            Err(_) => break,
        };
        let label = std::env::var(&label_var)
            .map_err(|_| DevSetupError::Env(format!("{label_var} not set")))?;
        let pin = std::env::var(&pin_var)
            .map_err(|_| DevSetupError::Env(format!("{pin_var} not set")))?;

        let signer = load_test_signer(config, &label, &pin, &mnemonic, derivation_path)?;
        signers.push(signer);
    }
    if signers.len() < 2 {
        return Err(DevSetupError::Federation(format!(
            "need at least 2 WALLET_TEST_*_MNEMONIC entries, found {}",
            signers.len()
        )));
    }
    Ok(signers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_path_rejects_missing() {
        let r = require_path(&PathBuf::from("/definitely/not/here.so"), "shim");
        assert!(r.is_err());
    }
}
