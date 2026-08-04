//! Live dev-shim Taproot (BIP-340) probe — proves the software Schnorr path.
//!
//! The dev shim (`libemvault_dev_hsm.so`) has no hardware Schnorr (SoftHSM 2
//! can't), so it traps `CKM_DEV_SCHNORR_BIP340` and signs in software behind the
//! PKCS#11 boundary. This exercises the whole path the way `emvault-pkcs11`
//! will: derive a leaf key → `DevBackend::taproot_signer().sign_schnorr(...)`
//! (which drives `C_SignInit`/`C_Sign` with the vendor mechanism) → verify the
//! BIP-340 signature against the leaf's x-only key with `secp256k1`.
//!
//! Self-contained: point it at a dev token whose slot seed the shim knows
//! (`DEV_HSM_CONFIG`), pass the token label + PIN. The wrapper in
//! `examples/run_dev_taproot_probe.sh` sets up a throwaway SoftHSM store.
//!
//! Env: `PKCS11_LIB`, `SOFTHSM2_LIB`, `SOFTHSM2_CONF`, `DEV_HSM_CONFIG`,
//! `DEV_TAP_LABEL`, `DEV_TAP_PIN`, `DEV_TAP_SO_PIN`.

#![allow(clippy::doc_markdown)]

use std::str::FromStr;

use emvault_dev_signer::{DevBackend, DevConfig, init_dev_token};
use emvault_pkcs11::bitcoin::bip32::DerivationPath;
use emvault_pkcs11::bitcoin::hashes::{Hash, sha256};
use emvault_pkcs11::bitcoin::secp256k1::{Message, Secp256k1};
use emvault_pkcs11::cryptoki::object::Attribute;
use emvault_pkcs11::{HsmBackend, Pkcs11Config, Pkcs11Session, SlotIdentifier, key_ops};

const NAME: &str = "dev-tap";

fn main() {
    match run() {
        Ok(()) => println!(
            "\n✅ Dev Taproot probe PASSED — dev-shim software Schnorr sign + verify all green."
        ),
        Err(e) => {
            eprintln!("\n❌ Dev Taproot probe FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let label = env("DEV_TAP_LABEL")?;
    let pin = env("DEV_TAP_PIN")?;
    let so_pin = std::env::var("DEV_TAP_SO_PIN").unwrap_or_else(|_| "1234".into());

    let cfg = DevConfig::from_env().map_err(|e| e.to_string())?;
    init_dev_token(&cfg, &label, &so_pin, &pin).map_err(|e| format!("init_dev_token: {e}"))?;

    let account = DerivationPath::from_str("m/86'/1'/0'").unwrap();
    let leaf = DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap();

    let pkcfg = Pkcs11Config::new(
        &cfg.shim_library_path,
        SlotIdentifier::label(&label),
        pin.clone(),
        account,
    );
    let session = Pkcs11Session::open(&pkcfg, &SlotIdentifier::label(&label), &pin)
        .map_err(|e| format!("open session: {e}"))?;
    let backend = DevBackend;

    let priv_label = key_ops::priv_label(NAME);
    clean(&session, NAME);

    let master = backend
        .derive_master_key(session.session(), &[], &priv_label)
        .map_err(|e| format!("derive_master_key: {e}"))?;
    println!("dev master fingerprint {}", master.fingerprint);

    let leaf_h = backend
        .derive_path(session.session(), master.key_handle, &leaf)
        .map_err(|e| format!("derive_path: {e}"))?;
    let xpub = backend
        .read_xpub(session.session(), leaf_h)
        .map_err(|e| format!("read_xpub: {e}"))?;
    let (xonly, _parity) = xpub.public_key.x_only_public_key();
    println!("leaf x-only pubkey: {xonly}");

    let sighash: [u8; 32] = *sha256::Hash::hash(b"emvault dev taproot probe").as_byte_array();
    println!("sighash: {}", hex::encode(sighash));

    let taproot = backend
        .taproot_signer()
        .ok_or("DevBackend advertises no taproot signer")?;
    let sig = taproot
        .sign_schnorr(session.session(), leaf_h, NAME, &leaf, &sighash)
        .map_err(|e| format!("sign_schnorr: {e}"))?;
    println!("BIP-340 signature: {sig}");

    let msg = Message::from_digest(sighash);
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &msg, &xonly)
        .map_err(|e| format!("schnorr verify: {e}"))?;
    println!("secp256k1 Schnorr verify: OK");

    // Regression: intercepting C_Sign must NOT disturb the ECDSA path — it still
    // forwards to SoftHSM. Sign the same leaf with ECDSA and verify.
    let ecdsa = backend
        .segwit_signer()
        .ok_or("DevBackend advertises no segwit signer")?;
    let esig = ecdsa
        .sign_ecdsa(session.session(), leaf_h, &sighash)
        .map_err(|e| format!("sign_ecdsa: {e}"))?;
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &esig, &xpub.public_key)
        .map_err(|e| format!("ecdsa verify: {e}"))?;
    println!("secp256k1 ECDSA verify (forward path intact): OK");

    clean(&session, NAME);
    Ok(())
}

fn clean(session: &Pkcs11Session, name: &str) {
    for lbl in [key_ops::priv_label(name), key_ops::pub_label(name)] {
        if let Ok(handles) = session
            .session()
            .find_objects(&[Attribute::Label(lbl.into_bytes())])
        {
            for h in handles {
                let _ = session.session().destroy_object(h);
            }
        }
    }
}

fn env(k: &str) -> Result<String, String> {
    std::env::var(k).map_err(|_| format!("{k} not set"))
}
