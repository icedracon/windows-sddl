# windows-sddl

[![crates.io](https://img.shields.io/crates/v/windows-sddl.svg)](https://crates.io/crates/windows-sddl)
[![docs.rs](https://img.shields.io/docsrs/windows-sddl)](https://docs.rs/windows-sddl)
[![CI](https://github.com/icedracon/windows-sddl/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/windows-sddl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Rust, **no-FFI** parser and builder for the Windows *self-relative*
`SECURITY_DESCRIPTOR` blob (MS-DTYP §2.4.6) — the binary form stored in
`nTSecurityDescriptor`, returned over LDAP, and found in registry hives and backup formats.

It works cross-platform against raw bytes: **no `windows` crate, no OS calls**, so you can read
and reason about Windows ACLs from Linux/macOS — for DFIR, ACL auditing, backup/migration
tooling, or an AD security scanner.

The crate is the portable parser layer in the
[`win32-min` ecosystem](https://github.com/icedracon/win32-min/blob/master/ECOSYSTEM.md).
It does not depend on `win32-min`: this separation keeps hostile/offline byte
parsing available on Windows, Linux, and macOS.

## Features

- Parse self-relative `SECURITY_DESCRIPTOR` → owner / group / DACL with typed ACEs
  (`AccessAllowed`, `AccessDenied`, and their *object* variants), preserving
  whether the DACL is absent, NULL, or present through `DaclKind`.
- Typed `AccessMask` bitflags (`WriteDacl`, `WriteOwner`, `GenericAll`, extended-right bits …).
- `Sid` and `Guid` types with binary + string parsing/formatting (`objectSid`, `S-1-5-…`).
- A table of Active-Directory extended-right GUIDs ([`rights`]) so an object ACE resolves into a
  concrete right: DCSync, Shadow Credentials, RBCD, cert enrollment, force-change-password, …
- Build helper (`build_rbcd_sd`) for emitting a self-relative SD with an allow ACE.
- **Never panics on malformed input** — hostile/truncated blobs return an error. Fuzz-tested.
- Rejects child ACL, ACE, GUID, and SID ranges that escape their declared parent container.

## Example

```rust
use windows_sddl::{parse, rights, AccessMask};

let sd = parse(&nt_security_descriptor_bytes)?;
// DCSync requires BOTH REPL_GET_CHANGES *and* REPL_GET_CHANGES_ALL on the same
// trustee — and only on the domain head. `is_dcsync_right` returns true for
// either GUID, so a single match is not a conclusion. Accumulate per trustee.
use std::collections::HashMap;
let mut got: HashMap<&windows_sddl::Sid, u8> = HashMap::new(); // 1 = GC, 2 = GC-All
for ace in sd.dacl.iter().flat_map(|d| &d.aces).filter(|a| a.is_allow()) {
    if ace.mask.contains(AccessMask::GENERIC_ALL) {
        println!("{} has GenericAll", ace.trustee);
    }
    if let Some(g) = &ace.object_type {
        if rights::REPL_GET_CHANGES.matches(g)     { *got.entry(&ace.trustee).or_default() |= 1; }
        if rights::REPL_GET_CHANGES_ALL.matches(g) { *got.entry(&ace.trustee).or_default() |= 2; }
    }
}
for (trustee, bits) in got {
    if bits == 3 {
        println!("{trustee} has BOTH REPL_GET_CHANGES + REPL_GET_CHANGES_ALL \
                  (DCSync-capable if this SD is the domain head)");
    }
}
```

Or from the CLI:

```sh
cargo run --example parse_sd -- 010004801400...   # a hex nTSecurityDescriptor
```

The example highlights dangerous allow ACEs relevant to Active Directory and
offline DFIR. Its inputs, boundaries, and companion workflows are documented
in the ecosystem's
[`RESEARCH-WORKFLOWS.md`](https://github.com/icedracon/win32-min/blob/master/RESEARCH-WORKFLOWS.md).

## Scope

Parsing + building of self-relative security descriptors, ACLs, ACEs, SIDs, and GUIDs, plus the
AD extended-right GUID table. **The SACL is not parsed today** — `SecurityDescriptor` carries
owner + group + DACL only, and a present SACL is skipped, not preserved. Non-standard ACE
types found inside the DACL are surfaced as `AceType::Other`. Conditional ACEs (SDDL string
form) are out of scope for now.

Despite the crate name, the implemented input is the binary self-relative
security-descriptor format. Complete parsing of the textual SDDL language is
not currently claimed.

## License

MIT © icedracon. Extracted from [ADhammer](https://github.com/icedracon/adhammer).
