//! [`DevBackend`] — `HsmBackend` implementation for the
//! `libasterism_dev_hsm.so` PKCS#11 shim.
//!
//! Knows the mechanism IDs and attribute IDs that the dev shim
//! registers. These are the shim's own vendor-defined IDs — it does not
//! pretend to be Utimaco or Thales. The shim is its own "vendor" for
//! the purposes of PKCS#11 mechanism registration.

use asterism_pkcs11::HsmBackend;
use cryptoki::mechanism::MechanismType;
use cryptoki::object::AttributeType;

/// Master-derivation mechanism ID. Mirrors
/// `libasterism_dev_hsm/src/constants.rs::CKM_DEV_BIP32_MASTER_DERIVE`.
/// The `mechanism_ids.rs` integration test asserts the values agree at
/// CI time.
pub const CKM_DEV_BIP32_MASTER_DERIVE: u64 = 0x8000_D001;
/// Child-derivation mechanism ID. Mirrors
/// `libasterism_dev_hsm/src/constants.rs::CKM_DEV_BIP32_CHILD_DERIVE`.
pub const CKM_DEV_BIP32_CHILD_DERIVE: u64 = 0x8000_D002;
/// Vendor attribute: 32-byte BIP-32 chain code.
pub const CKA_DEV_BIP32_CHAIN_CODE: u64 = 0x8000_D101;
/// Vendor attribute: 1-byte BIP-32 depth.
pub const CKA_DEV_BIP32_CHILD_DEPTH: u64 = 0x8000_D102;
/// Vendor attribute: 4-byte parent fingerprint.
pub const CKA_DEV_BIP32_PARENT_FINGERPRINT: u64 = 0x8000_D103;
/// Vendor attribute: 4-byte little-endian child index.
pub const CKA_DEV_BIP32_CHILD_INDEX: u64 = 0x8000_D104;

/// `HsmBackend` implementation for the dev shim
/// (`libasterism_dev_hsm.so`).
///
/// All trait method bodies inherit from `HsmBackend`'s default
/// implementations; `DevBackend` only supplies the vendor-defined
/// mechanism / attribute IDs. The shim defines its own seed-passing
/// convention (the seed in `pMechanism->pParameter`) which matches the
/// trait's default mechanism-parameter convention exactly.
#[derive(Debug, Clone, Copy, Default)]
pub struct DevBackend;

impl HsmBackend for DevBackend {
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

    fn backend_name(&self) -> &str {
        "dev"
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
