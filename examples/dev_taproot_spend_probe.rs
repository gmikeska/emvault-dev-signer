//! Live dev-shim Taproot **spend** probe — proves the full P2TR script-path
//! signing path end to end (Phase 5).
//!
//! Where `dev_taproot_probe` proves a single Schnorr signature, this probe
//! proves the whole `emvault-pkcs11` taproot signing branch against a real
//! wallet: it builds a `tr(NUMS, multi_a(2, …))` 2-of-3 federation descriptor
//! (via `emvault-core`), funds its address with a synthetic UTXO, builds a
//! spend PSBT with BDK (which populates the taproot PSBT fields), signs it with
//! two dev-HSM `Pkcs11Signer`s (each driving `DevBackend::taproot_signer` behind
//! the PKCS#11 boundary), then:
//!
//!   1. verifies both emitted `tap_script_sigs` are valid BIP-340 signatures
//!      over the recomputed tapscript sighash, and
//!   2. finalizes the PSBT and extracts a transaction with a non-empty witness.
//!
//! Self-contained: `examples/run_dev_taproot_spend_probe.sh` spins up a
//! throwaway SoftHSM store with three seeded slots and runs this.
//!
//! Env: `PKCS11_LIB`, `SOFTHSM2_LIB`, `SOFTHSM2_CONF`, `DEV_HSM_CONFIG`,
//! `DEV_TAP_PIN`, `DEV_TAP_SO_PIN`, and `DEV_TAP_LABELS` (comma-separated).

#![allow(clippy::doc_markdown)]
#![allow(clippy::too_many_lines)]

use std::str::FromStr;
use std::sync::Arc;

use bitcoin::bip32::DerivationPath;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version,
};
use emvault_core::bdk_wallet::signer::SignerOrdering;
use emvault_core::bdk_wallet::{KeychainKind, SignOptions, Wallet};
use emvault_core::{DescriptorBuilder, NetworkType, ScriptType, Signer};
use emvault_dev_signer::{DevConfig, init_dev_token, load_test_signer};
use emvault_pkcs11::NetworkPatchedSigner;

const NETWORK: Network = Network::Testnet;
const THRESHOLD: u32 = 2;
const FUND_SATS: u64 = 100_000;
const FEE_SATS: u64 = 1_000;

fn main() {
    match run() {
        Ok(()) => println!(
            "\n✅ Dev Taproot SPEND probe PASSED — 2-of-3 tr(NUMS,multi_a) script-path spend \
             signed by dev HSMs, both Schnorr sigs verify, PSBT finalizes."
        ),
        Err(e) => {
            eprintln!("\n❌ Dev Taproot spend probe FAILED: {e}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let cfg = DevConfig::from_env().map_err(|e| e.to_string())?;
    let pin = env("DEV_TAP_PIN")?;
    let so_pin = std::env::var("DEV_TAP_SO_PIN").unwrap_or_else(|_| "123456".into());
    let labels: Vec<String> = env("DEV_TAP_LABELS")?
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if labels.len() < 3 {
        return Err(format!(
            "need 3 token labels in DEV_TAP_LABELS, got {}",
            labels.len()
        ));
    }

    // BIP-86 account path; in Fixed mode the descriptor key is the signer's key
    // at exactly this path, so the input's full path == this path (empty leaf).
    let account = DerivationPath::from_str("m/86'/1'/0'").unwrap();

    // Initialize ALL tokens first — the dev shim scans SoftHSM for every
    // configured slot when it first loads its seed config, so every token must
    // already exist before the first signer is derived.
    for label in &labels {
        init_dev_token(&cfg, label, &so_pin, &pin).map_err(|e| format!("init {label}: {e}"))?;
    }
    // Then derive a Pkcs11Signer per token.
    let mut signers = Vec::new();
    for label in &labels {
        let s = load_test_signer(&cfg, label, &pin, &account)
            .map_err(|e| format!("load_test_signer {label}: {e}"))?;
        signers.push(s);
    }
    println!("loaded {} dev-HSM signers at {account}", signers.len());

    // 2-of-3 Taproot federation descriptor: tr(NUMS, multi_a(2, ...)).
    // The dev signers report Mainnet xpub kind; patch to the target network so
    // the descriptor's network check passes (the x-only key bytes are the same).
    let patched: Vec<NetworkPatchedSigner> = signers
        .iter()
        .map(|s| NetworkPatchedSigner::new(s.clone(), NETWORK))
        .collect();
    let mut builder = DescriptorBuilder::new(THRESHOLD, NetworkType::Bitcoin(NETWORK))
        .script_type(ScriptType::Tr);
    for s in &patched {
        builder
            .add_signer(s as &dyn Signer)
            .map_err(|e| e.to_string())?;
    }
    let descriptor = builder.build().map_err(|e| e.to_string())?;
    println!("descriptor: {descriptor}");
    if !descriptor.to_string().contains("multi_a(2,") {
        return Err("descriptor is not a taproot multi_a(2,...)".into());
    }

    // Single-keychain wallet from the (no-wildcard) taproot descriptor.
    let mut wallet = Wallet::create_single(descriptor.to_string())
        .network(NETWORK)
        .create_wallet_no_persist()
        .map_err(|e| format!("wallet: {e}"))?;
    let address = wallet.reveal_next_address(KeychainKind::External).address;
    println!("federation P2TR address: {address}");
    if !address.script_pubkey().is_p2tr() {
        return Err("federation address is not P2TR".into());
    }

    // Fund it with a synthetic confirmed-looking UTXO.
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([7u8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(FUND_SATS),
            script_pubkey: address.script_pubkey(),
        }],
    };
    let funded_op = OutPoint::new(funding.compute_txid(), 0);
    wallet.apply_unconfirmed_txs(vec![(funding.clone(), 0)]);
    if wallet.get_utxo(funded_op).is_none() {
        return Err("wallet did not register the synthetic funding UTXO".into());
    }

    // Register the threshold's worth of signers (2 of the 3) and build a spend
    // that drains back to the same address, minus fee.
    for s in signers.iter().take(THRESHOLD as usize) {
        wallet.add_signer(
            KeychainKind::External,
            SignerOrdering::default(),
            Arc::new(s.clone()),
        );
    }

    let mut psbt = {
        let mut b = wallet.build_tx();
        b.drain_wallet()
            .drain_to(address.script_pubkey())
            .fee_absolute(Amount::from_sat(FEE_SATS));
        b.finish().map_err(|e| format!("build_tx: {e}"))?
    };

    // Sign with the HSMs; hold finalization so we can inspect the raw sigs.
    let opts = SignOptions {
        trust_witness_utxo: true,
        try_finalize: false,
        ..Default::default()
    };
    wallet
        .sign(&mut psbt, opts)
        .map_err(|e| format!("sign: {e}"))?;

    // 1. Exactly `THRESHOLD` tap-script signatures, each a valid BIP-340 sig.
    let tap_sigs = psbt.inputs[0].tap_script_sigs.clone();
    println!("tap_script_sigs produced: {}", tap_sigs.len());
    if tap_sigs.len() != THRESHOLD as usize {
        return Err(format!(
            "expected {THRESHOLD} tap_script_sigs, got {}",
            tap_sigs.len()
        ));
    }
    let secp = Secp256k1::verification_only();
    let prevouts = [funding.output[0].clone()];
    for ((xonly, leaf_hash), sig) in &tap_sigs {
        let sighash = SighashCache::new(&psbt.unsigned_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                *leaf_hash,
                sig.sighash_type,
            )
            .map_err(|e| format!("recompute sighash: {e}"))?;
        let msg = Message::from_digest(sighash.to_byte_array());
        secp.verify_schnorr(&sig.signature, &msg, xonly)
            .map_err(|e| format!("BIP-340 verify failed for {xonly}: {e}"))?;
        println!("  ✓ Schnorr sig verifies for cosigner {xonly}");
    }

    // 2. Finalize and extract — proves the witness assembles for multi_a.
    let finalized = wallet
        .finalize_psbt(&mut psbt, SignOptions::default())
        .map_err(|e| format!("finalize: {e}"))?;
    if !finalized {
        return Err("PSBT did not finalize with the threshold sigs".into());
    }
    let tx = psbt.extract_tx().map_err(|e| format!("extract_tx: {e}"))?;
    if tx.input[0].witness.is_empty() {
        return Err("finalized tx has an empty witness".into());
    }
    println!(
        "finalized spend txid {} — witness items: {}",
        tx.compute_txid(),
        tx.input[0].witness.len()
    );

    Ok(())
}

fn env(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("missing env var {key}"))
}
