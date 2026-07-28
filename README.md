# windows-sddl

[![crates.io](https://img.shields.io/crates/v/windows-sddl.svg)](https://crates.io/crates/windows-sddl)
[![docs.rs](https://img.shields.io/docsrs/windows-sddl)](https://docs.rs/windows-sddl)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Rust, **no-FFI** parser and builder for the Windows *self-relative*
`SECURITY_DESCRIPTOR` blob (MS-DTYP §2.4.6) — the binary form stored in
`nTSecurityDescriptor`, returned over LDAP, and found in registry hives and backup formats.

It works cross-platform against raw bytes: **no `windows` crate, no OS calls**, so you can read
and reason about Windows ACLs from Linux/macOS — for DFIR, ACL auditing, backup/migration
tooling, or an AD security scanner.

## Features

- Parse self-relative `SECURITY_DESCRIPTOR` → owner / group / DACL with typed ACEs
  (`AccessAllowed`, `AccessDenied`, and their *object* variants).
- Typed `AccessMask` bitflags (`WriteDacl`, `WriteOwner`, `GenericAll`, extended-right bits …).
- `Sid` and `Guid` types with binary + string parsing/formatting (`objectSid`, `S-1-5-…`).
- A table of Active-Directory extended-right GUIDs ([`rights`]) so an object ACE resolves into a
  concrete right: DCSync, Shadow Credentials, RBCD, cert enrollment, force-change-password, …
- Build helper (`build_rbcd_sd`) for emitting a self-relative SD with an allow ACE.
- **Never panics on malformed input** — hostile/truncated blobs return an error. Fuzz-tested.

## Example

```rust
use windows_sddl::{parse, rights, AccessMask};

let sd = parse(&nt_security_descriptor_bytes)?;
for ace in sd.dacl.iter().flat_map(|d| &d.aces).filter(|a| a.is_allow()) {
    if ace.mask.contains(AccessMask::GENERIC_ALL) {
        println!("{} has GenericAll", ace.trustee);
    }
    if let Some(g) = &ace.object_type {
        if rights::is_dcsync_right(g) {
            println!("{} can DCSync", ace.trustee);
        }
    }
}
```

Or from the CLI:

```sh
cargo run --example parse_sd -- 010004801400...   # a hex nTSecurityDescriptor
```

## Scope

Parsing + building of self-relative security descriptors, ACLs, ACEs, SIDs, and GUIDs, plus the
AD extended-right GUID table. SACL/audit ACEs are preserved as `AceType::Other`. Conditional
ACEs (SDDL string form) are out of scope for now.

## License

MIT © icedracon. Extracted from [ADhammer](https://github.com/icedracon/adhammer).
