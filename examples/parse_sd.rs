//! Parse a self-relative SECURITY_DESCRIPTOR and print owner + who has dangerous rights.
//!
//! Feed it a hex blob (e.g. an `nTSecurityDescriptor` value):
//!   cargo run --example parse_sd -- 010004...
//! With no argument it parses a demo SD built by the crate.

use windows_sddl::{parse, rights, AccessMask};

fn main() {
    let bytes = match std::env::args().nth(1) {
        Some(hex) => (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>(),
        None => {
            windows_sddl::build_rbcd_sd(&windows_sddl::Sid::parse("S-1-5-21-1-2-3-1104").unwrap())
        }
    };

    let sd = parse(&bytes).expect("parse security descriptor");
    if let Some(o) = &sd.owner {
        println!("owner: {o}");
    }
    for ace in sd.dacl.iter().flat_map(|d| &d.aces) {
        if !ace.is_allow() {
            continue;
        }
        let mut notes = Vec::new();
        if ace.mask.contains(AccessMask::GENERIC_ALL) {
            notes.push("GenericAll".to_string());
        }
        if ace.mask.contains(AccessMask::WRITE_DAC) {
            notes.push("WriteDacl".to_string());
        }
        if ace.mask.contains(AccessMask::WRITE_OWNER) {
            notes.push("WriteOwner".to_string());
        }
        if let Some(g) = &ace.object_type {
            if rights::is_dcsync_right(g) {
                notes.push("DCSync".to_string());
            }
            if rights::is_enrollment_right(g) {
                notes.push("Cert-Enrollment".to_string());
            }
            if rights::KEY_CREDENTIAL_LINK.matches(g) {
                notes.push("Shadow-Credentials".to_string());
            }
            if rights::RBCD_ATTR.matches(g) {
                notes.push("RBCD".to_string());
            }
        }
        if !notes.is_empty() {
            println!("  {} → {}", ace.trustee, notes.join(", "));
        }
    }
}
