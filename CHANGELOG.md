# Changelog

All notable changes to `windows-sddl` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4] — 2026-09-06

### Documentation

- Correct the Scope section: the SACL is not parsed today
  (`SecurityDescriptor` carries owner + group + DACL only, and a present
  SACL is skipped, not preserved). `AceType::Other` is correctly scoped
  to non-standard ACE types found inside the DACL.
- Rewrite the README DCSync example. Previously it printed "can DCSync"
  on a single `is_dcsync_right` match; DCSync in fact requires **both**
  `REPL_GET_CHANGES` and `REPL_GET_CHANGES_ALL` on the same trustee, on
  the domain head. New example accumulates per trustee and only concludes
  DCSync-capable when both bits are set. `is_dcsync_right`'s own docstring
  already documented this — the example was the overclaim.

No code changes.

## [0.1.3] — 2026-09-01

### Security

- Reject non-self-relative descriptors, truncated or escaping ACL/ACE/SID
  ranges, impossible ACE counts, and zero/undersized ACE records instead of
  accepting ambiguous hostile input.
- Preserve the security-critical distinction between an absent DACL, a NULL
  DACL, and a present ACL through the new `DaclKind` field.

### Added

- Retain the descriptor control flags on `SecurityDescriptor` so downstream
  authorization tools can reason about `SE_DACL_PRESENT` and related state.
- Linked the offline dangerous-ACE audit example into the shared research
  workflow index and AI-readable documentation.
- Added a libFuzzer target for hostile security-descriptor input, scheduled
  fuzzing, RustSec advisory auditing, and weekly dependency monitoring.

## [0.1.2] — 2026-08-29

### Added

- Cross-platform CI, package validation, research-oriented metadata, and an
  AI-readable project index.
- Explicit ecosystem and scope documentation distinguishing binary
  self-relative descriptors from the textual SDDL language.

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
