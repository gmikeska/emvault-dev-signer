//! BIP-39 mnemonic → 64-byte BIP-32 seed conversion.
//!
//! Uses [`bip39::Mnemonic`] for word-list parsing and PBKDF2 stretching.
//! Mnemonic strings are accepted in any of the standard BIP-39 word
//! counts (12 / 15 / 18 / 21 / 24); shorter / longer phrases are
//! rejected by `Mnemonic::parse`.

use bip39::Mnemonic;
use secrecy::{ExposeSecret, SecretBox};

use crate::error::DevSetupError;

/// Convert a BIP-39 mnemonic phrase into a 64-byte BIP-32 seed.
///
/// `passphrase` is the optional BIP-39 25th-word salt — empty string is
/// the standard "no passphrase" case. The result is a [`SecretBox`] of
/// 64 bytes; callers feed it straight to
/// [`asterism_pkcs11::Pkcs11Signer::derive_from_seed`].
///
/// # Errors
///
/// Returns [`DevSetupError::InvalidMnemonic`] if the mnemonic doesn't
/// parse cleanly under the English wordlist.
pub fn mnemonic_to_seed(
    mnemonic_phrase: &str,
    passphrase: &str,
) -> Result<SecretBox<[u8; 64]>, DevSetupError> {
    let mnemonic = Mnemonic::parse(mnemonic_phrase)
        .map_err(|e| DevSetupError::InvalidMnemonic(e.to_string()))?;
    let seed = mnemonic.to_seed(passphrase);
    Ok(SecretBox::new(Box::new(seed)))
}

/// Like [`mnemonic_to_seed`] but with no passphrase. Convenience wrapper
/// for the common dev path (the `WALLET_TEST_*_MNEMONIC` env vars don't
/// carry a passphrase).
pub fn mnemonic_to_seed_no_passphrase(
    mnemonic_phrase: &str,
) -> Result<SecretBox<[u8; 64]>, DevSetupError> {
    mnemonic_to_seed(mnemonic_phrase, "")
}

/// Borrow the inner 64 bytes of a [`SecretBox<[u8; 64]>`] without
/// cloning. Provided so callers don't have to import `secrecy` just to
/// use the seed.
pub fn expose(seed: &SecretBox<[u8; 64]>) -> &[u8; 64] {
    seed.expose_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from BIP-39 §"Test Vectors":
    /// mnemonic = 12 × "abandon" + "about", passphrase = "TREZOR"
    const ABANDON_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         about";
    const ABANDON_TREZOR_SEED_HEX: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    #[test]
    fn known_test_vector_round_trips() {
        let seed = mnemonic_to_seed(ABANDON_MNEMONIC, "TREZOR").unwrap();
        let bytes = expose(&seed);
        assert_eq!(hex::encode(&bytes[..]), ABANDON_TREZOR_SEED_HEX);
    }

    #[test]
    fn no_passphrase_path_works() {
        let seed = mnemonic_to_seed_no_passphrase(ABANDON_MNEMONIC).unwrap();
        assert_eq!(seed.expose_secret().len(), 64);
    }

    #[test]
    fn invalid_mnemonic_fails() {
        let r = mnemonic_to_seed("not a real mnemonic", "");
        assert!(r.is_err());
    }
}
