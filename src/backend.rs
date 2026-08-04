//! [`DevBackend`] — `AttributeDerivation` implementation for the
//! `libemvault_dev_hsm.so` PKCS#11 shim.
//!
//! Knows the mechanism IDs and attribute IDs that the dev shim
//! registers. These are the shim's own vendor-defined IDs — it does not
//! pretend to be Utimaco or Thales. The shim is its own "vendor" for
//! the purposes of PKCS#11 mechanism registration.

use bitcoin::bip32::DerivationPath;
use bitcoin::secp256k1::schnorr;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{AttributeType, ObjectHandle};
use cryptoki::session::Session;
use emvault_pkcs11::{AttributeDerivation, HsmBackendError, TaprootSigner};

/// Master-derivation mechanism ID. Mirrors
/// `libemvault_dev_hsm/src/constants.rs::CKM_DEV_BIP32_MASTER_DERIVE`.
/// The `mechanism_ids.rs` integration test asserts the values agree at
/// CI time.
pub const CKM_DEV_BIP32_MASTER_DERIVE: u64 = 0x8000_D001;
/// Child-derivation mechanism ID. Mirrors
/// `libemvault_dev_hsm/src/constants.rs::CKM_DEV_BIP32_CHILD_DERIVE`.
pub const CKM_DEV_BIP32_CHILD_DERIVE: u64 = 0x8000_D002;
/// Schnorr/BIP-340 signing mechanism ID. Mirrors
/// `libemvault_dev_hsm/src/constants.rs::CKM_DEV_SCHNORR_BIP340`. The shim
/// signs it in software (SoftHSM has no Schnorr); the `mechanism_ids.rs`
/// integration test asserts the value agrees.
pub const CKM_DEV_SCHNORR_BIP340: u64 = 0x8000_D003;
/// Vendor attribute: 32-byte BIP-32 chain code.
pub const CKA_DEV_BIP32_CHAIN_CODE: u64 = 0x8000_D101;
/// Vendor attribute: 1-byte BIP-32 depth.
pub const CKA_DEV_BIP32_CHILD_DEPTH: u64 = 0x8000_D102;
/// Vendor attribute: 4-byte parent fingerprint.
pub const CKA_DEV_BIP32_PARENT_FINGERPRINT: u64 = 0x8000_D103;
/// Vendor attribute: 4-byte little-endian child index.
pub const CKA_DEV_BIP32_CHILD_INDEX: u64 = 0x8000_D104;

/// `AttributeDerivation` implementation for the dev shim
/// (`libemvault_dev_hsm.so`).
///
/// The derive/read bodies come from the `HsmBackend` blanket impl over
/// implementations; `DevBackend` only supplies the vendor-defined
/// mechanism / attribute IDs. The shim defines its own seed-passing
/// convention (the seed in `pMechanism->pParameter`) which matches the
/// trait's default mechanism-parameter convention exactly.
#[derive(Debug, Clone, Copy, Default)]
pub struct DevBackend;

impl AttributeDerivation for DevBackend {
    fn master_derive_mechanism(&self) -> MechanismType {
        MechanismType::new_vendor_defined(CKM_DEV_BIP32_MASTER_DERIVE)
            .expect("CKM_DEV_BIP32_MASTER_DERIVE >= CKM_VENDOR_DEFINED")
    }

    fn child_derive_mechanism(&self) -> MechanismType {
        MechanismType::new_vendor_defined(CKM_DEV_BIP32_CHILD_DERIVE)
            .expect("CKM_DEV_BIP32_CHILD_DERIVE >= CKM_VENDOR_DEFINED")
    }

    fn chain_code_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_DEV_BIP32_CHAIN_CODE)
    }

    fn depth_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_DEV_BIP32_CHILD_DEPTH)
    }

    fn parent_fingerprint_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_DEV_BIP32_PARENT_FINGERPRINT)
    }

    fn child_index_attribute(&self) -> AttributeType {
        AttributeType::VendorDefined(CKA_DEV_BIP32_CHILD_INDEX)
    }

    fn backend_name(&self) -> &'static str {
        "dev"
    }

    /// The dev shim signs Taproot (BIP-340 Schnorr) in software behind the
    /// PKCS#11 boundary, so `DevBackend` advertises a Taproot signer. This is
    /// what gives a mixed-vendor federation (dev + Securosys) a working Taproot
    /// path on both sides.
    fn taproot_signer(&self) -> Option<&dyn TaprootSigner> {
        Some(&DEV_TAPROOT_SIGNER)
    }
}

/// Taproot (BIP-340 Schnorr) signer for the dev shim.
///
/// Signs through the shim's vendor `CKM_DEV_SCHNORR_BIP340` mechanism —
/// `C_SignInit` + `C_Sign` over the PKCS#11 session, exactly like the ECDSA
/// path uses `CKM_ECDSA`. The shim performs the software Schnorr. Signing is
/// **by key handle** (script-path, untweaked leaf), so `label`/`full_path` —
/// which the Securosys TSB transport needs to name its key — are unused here.
#[derive(Debug, Clone, Copy, Default)]
pub struct DevTaprootSigner;

/// Shared instance wired into [`DevBackend::taproot_signer`].
pub const DEV_TAPROOT_SIGNER: DevTaprootSigner = DevTaprootSigner;

impl TaprootSigner for DevTaprootSigner {
    fn sign_schnorr(
        &self,
        session: &Session,
        key: ObjectHandle,
        _label: &str,
        _full_path: &DerivationPath,
        sighash: &[u8; 32],
    ) -> Result<schnorr::Signature, HsmBackendError> {
        let mech_type = MechanismType::new_vendor_defined(CKM_DEV_SCHNORR_BIP340)
            .map_err(|e| HsmBackendError::Signing(format!("vendor mechanism id: {e}")))?;
        let mech = Mechanism::VendorDefined(VendorDefinedMechanism::new(mech_type, None::<&()>));
        let raw = session
            .sign(&mech, key, sighash)
            .map_err(|e| HsmBackendError::Signing(e.to_string()))?;
        schnorr::Signature::from_slice(&raw).map_err(|e| HsmBackendError::Signing(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_is_dev() {
        assert_eq!(DevBackend.backend_name(), "dev");
    }

    #[test]
    fn mechanism_ids_match_documented_values() {
        assert_eq!(CKM_DEV_BIP32_MASTER_DERIVE, 0x8000_D001);
        assert_eq!(CKM_DEV_BIP32_CHILD_DERIVE, 0x8000_D002);
        assert_eq!(CKA_DEV_BIP32_CHAIN_CODE, 0x8000_D101);
        assert_eq!(CKA_DEV_BIP32_CHILD_DEPTH, 0x8000_D102);
        assert_eq!(CKA_DEV_BIP32_PARENT_FINGERPRINT, 0x8000_D103);
        assert_eq!(CKA_DEV_BIP32_CHILD_INDEX, 0x8000_D104);
    }
}
