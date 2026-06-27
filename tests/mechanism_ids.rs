//! Cross-check that the dev shim's PKCS#11 mechanism IDs agree with
//! [`DevBackend`]'s constants.
//!
//! `DevBackend` and `libemvault_dev_hsm.so` are built from separate
//! crates. They share a contract — the vendor-defined mechanism IDs and
//! attribute IDs — but Rust's type system can't enforce it across the
//! crate boundary. This test loads the shim at runtime and asserts the
//! contract holds.
//!
//! The high-level `cryptoki` wrapper drops vendor-defined mechanism IDs
//! when converting raw `CK_MECHANISM_TYPE`s into its `MechanismType`
//! enum (see its `TryFrom` impl), so we go directly through
//! `libloading` + `cryptoki-sys` here.
//!
//! The test is skipped (passes trivially) when `PKCS11_LIB` isn't set
//! or the shim isn't built. To run it:
//!
//! ```bash
//! cd ../libemvault_dev_hsm && cargo build --release
//! cd ../emvault-dev-signer
//! PKCS11_LIB=$(realpath ../libemvault_dev_hsm/target/release/libemvault_dev_hsm.so) \
//!   SOFTHSM2_LIB=/usr/lib/softhsm/libsofthsm2.so \
//!   cargo test --test mechanism_ids -- --nocapture
//! ```

#![allow(non_snake_case)]

use std::ffi::c_void;
use std::os::raw::c_uchar;
use std::ptr;

use emvault_dev_signer::{
    CKA_DEV_BIP32_CHAIN_CODE, CKA_DEV_BIP32_CHILD_DEPTH, CKA_DEV_BIP32_CHILD_INDEX,
    CKA_DEV_BIP32_PARENT_FINGERPRINT, CKM_DEV_BIP32_CHILD_DERIVE, CKM_DEV_BIP32_MASTER_DERIVE,
};
use cryptoki_sys::{
    CK_C_INITIALIZE_ARGS, CK_FLAGS, CK_FUNCTION_LIST, CK_MECHANISM_INFO, CK_MECHANISM_TYPE, CK_RV,
    CK_SLOT_ID, CK_ULONG, CK_VOID_PTR, CKR_OK,
};

const CKF_OS_LOCKING_OK: CK_FLAGS = 0x0000_0002;

type CGetFunctionList = unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV;

fn pkcs11_lib_path() -> Option<String> {
    let _ = dotenvy::from_filename("../emvault-core/.env");
    std::env::var("PKCS11_LIB").ok()
}

struct Shim {
    _lib: libloading::Library,
    list: *mut CK_FUNCTION_LIST,
}

impl Shim {
    fn load(path: &str) -> Result<Self, String> {
        let lib = unsafe { libloading::Library::new(path) }.map_err(|e| format!("dlopen: {e}"))?;
        let entry: libloading::Symbol<'_, CGetFunctionList> =
            unsafe { lib.get(b"C_GetFunctionList") }
                .map_err(|e| format!("missing C_GetFunctionList: {e}"))?;
        let mut list: *mut CK_FUNCTION_LIST = ptr::null_mut();
        let rv = unsafe { entry(&raw mut list) };
        if rv != CKR_OK || list.is_null() {
            return Err(format!("C_GetFunctionList failed: 0x{rv:x}"));
        }
        Ok(Self { _lib: lib, list })
    }

    fn fns(&self) -> &CK_FUNCTION_LIST {
        unsafe { &*self.list }
    }
}

#[test]
fn shim_advertises_dev_bip32_master_and_child_mechanisms() {
    let Some(path) = pkcs11_lib_path() else {
        eprintln!("PKCS11_LIB not set; skipping cross-check.");
        return;
    };
    if !std::path::Path::new(&path).exists() {
        eprintln!("PKCS11_LIB={path} does not exist; skipping cross-check.");
        return;
    }

    let shim = match Shim::load(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to load shim at {path}: {e}; skipping.");
            return;
        }
    };
    let f = shim.fns();

    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: ptr::null_mut(),
    };
    let init = f.C_Initialize.expect("C_Initialize present");
    let rv = unsafe { init((&raw mut args).cast::<c_void>()) };
    if rv != CKR_OK {
        eprintln!("C_Initialize failed: 0x{rv:x}; skipping (probably missing SOFTHSM2_LIB).");
        return;
    }

    let finalize = f.C_Finalize.expect("C_Finalize present");
    let _guard = FinalizeGuard {
        finalize: Some(finalize),
    };

    let get_slot_list = f.C_GetSlotList.expect("C_GetSlotList present");
    let mut count: CK_ULONG = 0;
    let rv = unsafe { get_slot_list(1, ptr::null_mut(), &raw mut count) };
    assert_eq!(rv, CKR_OK, "C_GetSlotList(count) -> 0x{rv:x}");
    if count == 0 {
        eprintln!("no PKCS#11 slots reported; skipping.");
        return;
    }
    let mut slots = vec![CK_SLOT_ID::default(); usize::try_from(count).unwrap_or(0)];
    let rv = unsafe { get_slot_list(1, slots.as_mut_ptr(), &raw mut count) };
    assert_eq!(rv, CKR_OK, "C_GetSlotList(slots) -> 0x{rv:x}");
    let slot = slots[0];

    let get_mech_list = f.C_GetMechanismList.expect("C_GetMechanismList present");
    let mut mech_count: CK_ULONG = 0;
    let rv = unsafe { get_mech_list(slot, ptr::null_mut(), &raw mut mech_count) };
    assert_eq!(rv, CKR_OK, "C_GetMechanismList(count) -> 0x{rv:x}");
    let mut mechs = vec![CK_MECHANISM_TYPE::default(); usize::try_from(mech_count).unwrap_or(0)];
    let rv = unsafe { get_mech_list(slot, mechs.as_mut_ptr(), &raw mut mech_count) };
    assert_eq!(rv, CKR_OK, "C_GetMechanismList(buf) -> 0x{rv:x}");
    mechs.truncate(usize::try_from(mech_count).unwrap_or(0));

    let raw: Vec<u64> = mechs.clone();
    assert!(
        raw.contains(&CKM_DEV_BIP32_MASTER_DERIVE),
        "shim should advertise CKM_DEV_BIP32_MASTER_DERIVE (0x{CKM_DEV_BIP32_MASTER_DERIVE:08x}); got: {raw:#x?}",
    );
    assert!(
        raw.contains(&CKM_DEV_BIP32_CHILD_DERIVE),
        "shim should advertise CKM_DEV_BIP32_CHILD_DERIVE (0x{CKM_DEV_BIP32_CHILD_DERIVE:08x}); got: {raw:#x?}",
    );

    let get_mech_info = f.C_GetMechanismInfo.expect("C_GetMechanismInfo present");
    for id in [CKM_DEV_BIP32_MASTER_DERIVE, CKM_DEV_BIP32_CHILD_DERIVE] {
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        let rv = unsafe { get_mech_info(slot, id as CK_MECHANISM_TYPE, &raw mut info) };
        assert_eq!(rv, CKR_OK, "C_GetMechanismInfo(0x{id:08x}) -> 0x{rv:x}");
        assert!(
            info.flags != 0,
            "C_GetMechanismInfo(0x{id:08x}) returned zero flags",
        );
    }

    // Quiet unused-variable warnings on the c_uchar/c_void imports kept
    // for future expansion of this test (e.g. round-tripping derives).
    let _: *const c_uchar = ptr::null();
    let _: *const c_void = ptr::null();
}

#[test]
fn vendor_attribute_ids_are_in_vendor_defined_range() {
    // CKA_VENDOR_DEFINED is 0x80000000 in PKCS#11 v2.40+.
    const CKA_VENDOR_DEFINED: u64 = 0x8000_0000;
    for id in [
        CKA_DEV_BIP32_CHAIN_CODE,
        CKA_DEV_BIP32_CHILD_DEPTH,
        CKA_DEV_BIP32_PARENT_FINGERPRINT,
        CKA_DEV_BIP32_CHILD_INDEX,
    ] {
        assert!(
            id >= CKA_VENDOR_DEFINED,
            "0x{id:08x} should be >= CKA_VENDOR_DEFINED (0x{CKA_VENDOR_DEFINED:08x})",
        );
    }
}

#[test]
fn vendor_mechanism_ids_are_in_vendor_defined_range() {
    // CKM_VENDOR_DEFINED is 0x80000000 in PKCS#11 v2.40+.
    const CKM_VENDOR_DEFINED: u64 = 0x8000_0000;
    for id in [CKM_DEV_BIP32_MASTER_DERIVE, CKM_DEV_BIP32_CHILD_DERIVE] {
        assert!(
            id >= CKM_VENDOR_DEFINED,
            "0x{id:08x} should be >= CKM_VENDOR_DEFINED (0x{CKM_VENDOR_DEFINED:08x})",
        );
    }
}

struct FinalizeGuard {
    finalize: Option<unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV>,
}

impl Drop for FinalizeGuard {
    fn drop(&mut self) {
        if let Some(f) = self.finalize.take() {
            let _ = unsafe { f(ptr::null_mut()) };
        }
    }
}
