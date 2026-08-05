# Changelog

All notable changes to `emvault-dev-signer` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

## [0.8.0] - Unreleased

### Added
- **Dev-shim Taproot (BIP-340) signer.** `DevTaprootSigner` +
  `DevBackend::taproot_signer` perform software Schnorr behind the PKCS#11
  boundary via the vendor mechanism `CKM_DEV_SCHNORR_BIP340`, giving a
  mixed-vendor federation (dev + hardware HSM) a working Taproot cosigner.
- `dev_taproot_spend_probe` example (+ runner): a full 2-of-3
  `tr(NUMS, multi_a)` script-path spend signed by dev SoftHSM keys, with both
  BIP-340 signatures verified and the PSBT finalized.

## [0.7.0] - 2026-08-03

### Changed
- Released in lockstep with the suite-wide v0.7.0 update; no functional changes.

## [0.6.0] - 2026-07-29

### Changed
- Released in lockstep with the suite-wide reorg-reconciliation update (v0.6.0).
- Documentation updates.

## [0.5.0] - 2026-07-27

### Changed
- Dependency and lockfile refresh; version realigned across the emvault suite.

## [0.4.0] - 2026-07-22

### Changed
- README/documentation and release-metadata updates only.

## [0.3.0] - 2026-07-13

### Changed
- Documentation and release-metadata updates only.
