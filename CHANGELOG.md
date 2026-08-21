# Changelog

All notable changes to `windows-sddl` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] — 2026-08-03

### Fixed
- **`AccessMask::from_bits_truncate` was dropping `READ_PROP`** — the
  LAPS-read ACE (0x20) was parsed as an empty mask, silently hiding
  every LAPS-relevant ACE in downstream audits.
- Full `AccessMask` bitflag audit against MS-DTYP — all 30+ generic /
  standard / object-specific bits now round-trip.

## [0.1.0] — 2026-07-28

Initial release: pure-Rust, no-FFI parser and builder for Windows
self-relative `SECURITY_DESCRIPTOR` blobs.

### Added
- Parse + serialise SD header + owner/group SIDs + DACL/SACL (ACL headers
  + individual ACEs: allow / deny / audit + object-specific variants).
- SID parse + format (`S-R-I-S1-S2-…`), including 6-byte identifier
  authority.
- ACE `AccessMask` bitflags (generic / standard / object-specific,
  MS-DTYP compliant).
- Zero external FFI (no `windows-rs` or `winapi` dep) — pure Rust
  parsing of the binary format.
