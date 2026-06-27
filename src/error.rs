//! Error types for `emvault-dev-signer`.

/// Errors raised by dev-tooling helpers (`init_dev_token`,
/// `load_test_signer`, `setup_dev_federation`).
#[derive(Debug, thiserror::Error)]
pub enum DevSetupError {
    /// PKCS#11-level failure surfaced from [`emvault_pkcs11`].
    #[error("PKCS#11 error: {0}")]
    Pkcs11(#[from] emvault_pkcs11::Pkcs11Error),

    /// `cryptoki` error surfaced from a direct call (token init, slot
    /// listing, etc.).
    #[error("cryptoki error: {0}")]
    Cryptoki(#[from] cryptoki::error::Error),

    /// `.env` file load failed or a required variable was missing.
    #[error("environment configuration error: {0}")]
    Env(String),

    /// Filesystem path didn't exist or wasn't readable.
    #[error("path missing or unreadable: {0}")]
    Path(String),

    /// The dev federation `.env` was structurally invalid (e.g. fewer
    /// than two `HSM_DEV_*_LABEL` entries).
    #[error("dev federation misconfigured: {0}")]
    Federation(String),

    /// I/O error while reading config files.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
