//! Dev/CI tooling for getting `Pkcs11Signer`s wired up against the
//! `libemvault_dev_hsm.so` shim with as little ceremony as possible.
//!
//! ## Mnemonics live in the shim
//!
//! `emvault-dev-signer` does **not** parse BIP-39, derive seeds, or
//! pass seed material across the PKCS#11 ABI. The shim
//! (`libemvault_dev_hsm.so`) reads `DEV_HSM_SLOT_{i}_MNEMONIC` env
//! vars (or a TOML config at `$DEV_HSM_CONFIG`) at first
//! `C_DeriveKey(CKM_DEV_BIP32_MASTER_DERIVE)` and substitutes the
//! preloaded seed for the session's slot. From this crate's
//! perspective, derivation is just a PKCS#11 call. See
//! `libemvault_dev_hsm/README.md` for the seed-config schema.
//!
//! ## Entry points
//!
//! - [`init_dev_token`] — programmatic `pkcs11-tool --init-token`
//!   equivalent, so tests can reset their tokens without shelling out.
//! - [`load_test_signer`] — opens a session against a token and calls
//!   [`emvault_pkcs11::Pkcs11Signer::derive_from_seed`] with an empty
//!   seed, letting the shim pull the right preloaded seed for the
//!   token's slot.
//! - [`setup_dev_federation`] — reads the `HSM_DEV_{i}_LABEL` /
//!   `HSM_DEV_{i}_PIN` pairs out of `.env` and produces a vec of
//!   fully-configured `Pkcs11Signer`s.

use std::path::{Path, PathBuf};

use emvault_pkcs11::Pkcs11Signer;
use emvault_pkcs11::config::SlotIdentifier;
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use crate::backend::DevBackend;
use crate::error::DevSetupError;

/// Default network for dev signers — testnet matches the SoftHSM-backed
/// integration test suite.
const DEFAULT_NETWORK: Network = Network::Testnet;

/// Configuration for the dev HSM environment.
///
/// Strictly the path to `libemvault_dev_hsm.so`. SoftHSM library /
/// config paths live in shim-side env vars (`SOFTHSM2_LIB`,
/// `SOFTHSM2_CONF`); seed material lives in shim-side env vars
/// (`DEV_HSM_SLOT_*_MNEMONIC`) or a TOML file (`DEV_HSM_CONFIG`).
#[derive(Clone, Debug)]
pub struct DevConfig {
    /// Path to `libemvault_dev_hsm.so`.
    pub shim_library_path: PathBuf,
}

impl DevConfig {
    /// Read the shim path from `PKCS11_LIB`.
    ///
    /// # Errors
    ///
    /// Returns [`DevSetupError::Env`] if `PKCS11_LIB` is unset, or
    /// [`DevSetupError::Path`] if the path doesn't exist.
    pub fn from_env() -> Result<Self, DevSetupError> {
        let shim = std::env::var("PKCS11_LIB")
            .map_err(|_| DevSetupError::Env("PKCS11_LIB not set".into()))?;
        let cfg = Self {
            shim_library_path: PathBuf::from(shim),
        };
        cfg.check_paths()?;
        Ok(cfg)
    }

    fn check_paths(&self) -> Result<(), DevSetupError> {
        require_path(&self.shim_library_path, "shim_library_path")
    }
}

fn require_path(p: &Path, what: &str) -> Result<(), DevSetupError> {
    if !p.exists() {
        return Err(DevSetupError::Path(format!(
            "{what} {} does not exist",
            p.display()
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
    // The dev shim is process-global. Once any prior `Pkcs11::initialize`
    // has marked it initialized, subsequent calls return
    // `CKR_CRYPTOKI_ALREADY_INITIALIZED`. That's correct PKCS#11
    // semantics for re-binding to an already-loaded module — treat it
    // as success.
    match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) => {}
        Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiAlreadyInitialized,
            _,
        )) => {
            log::debug!("dev shim already initialized; reusing existing C_Initialize");
        }
        Err(e) => return Err(e.into()),
    }

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
        .ok_or_else(|| DevSetupError::Env("no uninitialized SoftHSM slot available".into()))?;

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

/// Open a session, derive a signer at `derivation_path`, and return it
/// ready for federation construction.
///
/// The shim provides seed material from its own configuration
/// (`DEV_HSM_SLOT_{i}_MNEMONIC` or `DEV_HSM_CONFIG`). The empty `&[]`
/// seed passed to [`Pkcs11Signer::derive_from_seed`] tells the shim
/// "use whatever seed you have configured for this session's slot."
///
/// This is the dev equivalent of a key ceremony: in production, the
/// ceremony is a formal multi-HSM process with key custodians and
/// scripts. Here we collapse it to one call.
///
/// # Errors
///
/// Returns [`DevSetupError`] for missing tokens or any HSM-level
/// failure.
pub fn load_test_signer(
    config: &DevConfig,
    token_label: &str,
    pin: &str,
    derivation_path: &DerivationPath,
) -> Result<Pkcs11Signer, DevSetupError> {
    let pkcs11_cfg = emvault_pkcs11::Pkcs11Config::new(
        &config.shim_library_path,
        SlotIdentifier::label(token_label),
        pin.to_string(),
        derivation_path.clone(),
        Box::new(DevBackend),
    );
    let session = emvault_pkcs11::Pkcs11Session::open(
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
        // Empty seed: the shim will look up the preloaded seed for
        // this session's slot from its own configuration.
        &[],
    )?;
    Ok(signer)
}

/// Set up a complete dev federation from `.env`.
///
/// Reads `HSM_DEV_{i}_LABEL` / `HSM_DEV_{i}_PIN` pairs for `i` from 1
/// upwards (stopping at the first gap) and returns a vec of
/// `Pkcs11Signer`s ready to wrap into a [`emvault_core::Federation`].
/// Mnemonics are **not** read here; the shim handles seed material
/// internally based on each token's slot id.
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
        let label_var = format!("HSM_DEV_{i}_LABEL");
        let pin_var = format!("HSM_DEV_{i}_PIN");

        let Ok(label) = std::env::var(&label_var) else {
            break;
        };
        let pin = std::env::var(&pin_var)
            .map_err(|_| DevSetupError::Env(format!("{pin_var} not set")))?;

        let signer = load_test_signer(config, &label, &pin, derivation_path)?;
        signers.push(signer);
    }
    if signers.len() < 2 {
        return Err(DevSetupError::Federation(format!(
            "need at least 2 HSM_DEV_*_LABEL entries, found {}",
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
