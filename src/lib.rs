//! # windows-sddl
//!
//! A pure-Rust, **no-FFI** parser and builder for the Windows *self-relative*
//! `SECURITY_DESCRIPTOR` blob (MS-DTYP §2.4.6) — the binary form stored in
//! `nTSecurityDescriptor`, returned over LDAP, and found in registry hives and backup
//! formats. It works cross-platform against raw bytes: no `windows` crate, no OS calls.
//!
//! It also ships the [`Sid`]/[`Guid`] types and a table of Active-Directory extended-right
//! GUIDs ([`rights`]) so a generic-looking ACE mask can be resolved into a concrete right
//! (DCSync, Shadow Credentials, RBCD, cert enrollment, …).
//!
//! ## Example
//!
//! ```
//! use windows_sddl::{parse, AccessMask};
//!
//! // A self-relative SD with one ACCESS_ALLOWED ACE granting full control to a trustee:
//! let sd_bytes = windows_sddl::build_rbcd_sd(&windows_sddl::Sid::parse("S-1-5-21-1-2-3-1104").unwrap());
//! let sd = parse(&sd_bytes).unwrap();
//! let ace = &sd.dacl.unwrap().aces[0];
//! assert!(ace.is_allow());
//! assert!(ace.mask.contains(AccessMask::WRITE_DAC));
//! ```
//!
//! ## Uses
//!
//! - DFIR / forensics: read ACLs out of offline hives or LDAP dumps without a Windows host.
//! - ACL auditing: enumerate who has `WriteDacl`/`WriteOwner`/`GenericAll` on an object.
//! - Backup / migration tooling: inspect or rebuild security descriptors portably.

use bitflags::bitflags;

pub mod rights;
pub mod sid;

pub use sid::{Guid, Sid};

/// Serialize a SID to its binary (`objectSid`) form. (Convenience alias for [`Sid::to_bytes`].)
pub fn sid_to_bytes(sid: &Sid) -> Vec<u8> {
    sid.to_bytes()
}

/// Build a `msDS-AllowedToActOnBehalfOfOtherIdentity`-style security descriptor granting
/// `trustee` full control (the RBCD primitive): a self-relative SD with one allow ACE, owner
/// `BUILTIN\Administrators`. Handy for tests and for tooling that needs to *write* an SD.
pub fn build_rbcd_sd(trustee: &Sid) -> Vec<u8> {
    let owner = Sid {
        revision: 1,
        identifier_authority: 5,
        sub_authorities: vec![32, 544],
    };
    let ownerb = owner.to_bytes();
    let trusteeb = trustee.to_bytes();

    // ACCESS_ALLOWED_ACE: type 0, flags 0, size, mask (0x000F01FF = full control), sid.
    let ace_size = (4 + 4 + trusteeb.len()) as u16;
    let mut ace = vec![0x00u8, 0x00];
    ace.extend_from_slice(&ace_size.to_le_bytes());
    ace.extend_from_slice(&0x000F_01FFu32.to_le_bytes());
    ace.extend_from_slice(&trusteeb);

    // ACL: revision 2, size, ace_count 1.
    let dacl_size = (8 + ace.len()) as u16;
    let mut dacl = vec![0x02u8, 0x00];
    dacl.extend_from_slice(&dacl_size.to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes());
    dacl.extend_from_slice(&0u16.to_le_bytes());
    dacl.extend_from_slice(&ace);

    // Self-relative SD: owner = group = BA, DACL present.
    let owner_off = 20u32;
    let group_off = 20 + ownerb.len() as u32;
    let dacl_off = group_off + ownerb.len() as u32;
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // SE_SELF_RELATIVE | SE_DACL_PRESENT
    sd.extend_from_slice(&owner_off.to_le_bytes());
    sd.extend_from_slice(&group_off.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // SACL offset
    sd.extend_from_slice(&dacl_off.to_le_bytes());
    sd.extend_from_slice(&ownerb); // owner
    sd.extend_from_slice(&ownerb); // group
    sd.extend_from_slice(&dacl);
    sd
}

#[derive(Debug, thiserror::Error)]
pub enum SddlError {
    #[error("buffer too short at {0}")]
    Truncated(&'static str),
    #[error("bad ACE sid")]
    BadSid,
    #[error("malformed security descriptor: {0}")]
    Malformed(&'static str),
}

type Result<T> = std::result::Result<T, SddlError>;

bitflags! {
    /// ACCESS_MASK bits (MS-DTYP §2.4.3 + AD-specific extended rights).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AccessMask: u32 {
        const CREATE_CHILD    = 0x0000_0001;
        const DELETE_CHILD    = 0x0000_0002;
        const LIST_CHILDREN   = 0x0000_0004;
        const SELF            = 0x0000_0008; // validated write
        const READ_PROP       = 0x0000_0010; // read property (scoped by object GUID)
        const WRITE_PROP      = 0x0000_0020; // write property (scoped by object GUID)
        const DELETE_TREE     = 0x0000_0040;
        const LIST_OBJECT     = 0x0000_0080;
        const CONTROL_ACCESS  = 0x0000_0100; // extended right (scoped by object GUID)
        const DELETE          = 0x0001_0000;
        const READ_CONTROL    = 0x0002_0000;
        const WRITE_DAC       = 0x0004_0000;
        const WRITE_OWNER     = 0x0008_0000;
        const SYNCHRONIZE     = 0x0010_0000;
        const ACCESS_SYSTEM_SECURITY = 0x0100_0000;
        const GENERIC_ALL     = 0x1000_0000;
        const GENERIC_EXECUTE = 0x2000_0000;
        const GENERIC_WRITE   = 0x4000_0000;
        const GENERIC_READ    = 0x8000_0000;
    }
}

/// ACE header type byte (MS-DTYP §2.4.4). Allow/deny + their object variants; everything else
/// is preserved as [`AceType::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AceType {
    AccessAllowed,
    AccessDenied,
    AccessAllowedObject,
    AccessDeniedObject,
    Other(u8),
}

#[derive(Clone, Debug)]
pub struct Ace {
    pub ace_type: AceType,
    pub flags: u8,
    pub mask: AccessMask,
    pub trustee: Sid,
    /// Present for *object* ACEs: which property-set / extended-right / child-class this grants.
    pub object_type: Option<Guid>,
    pub inherited_object_type: Option<Guid>,
}

impl Ace {
    pub fn is_allow(&self) -> bool {
        matches!(
            self.ace_type,
            AceType::AccessAllowed | AceType::AccessAllowedObject
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Acl {
    pub aces: Vec<Ace>,
}

#[derive(Clone, Debug, Default)]
pub struct SecurityDescriptor {
    /// Raw SECURITY_DESCRIPTOR control word (MS-DTYP 2.4.6).
    pub control: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    /// Distinguishes an omitted DACL from a present NULL DACL and a concrete ACL.
    pub dacl_kind: DaclKind,
    pub dacl: Option<Acl>,
}

/// Semantic state of the DACL. A NULL DACL grants unrestricted access and must not be
/// treated like an empty concrete ACL.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DaclKind {
    #[default]
    NotPresent,
    Null,
    Present,
}

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;

fn u16le(b: &[u8], o: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2)
            .ok_or(SddlError::Truncated("u16"))?
            .try_into()
            .unwrap(),
    ))
}
fn u32le(b: &[u8], o: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4)
            .ok_or(SddlError::Truncated("u32"))?
            .try_into()
            .unwrap(),
    ))
}
fn sid_at(b: &[u8], o: usize) -> Result<Sid> {
    let count = *b.get(o + 1).ok_or(SddlError::Truncated("sid"))? as usize;
    let end = o + 8 + count * 4;
    Sid::from_bytes(b.get(o..end).ok_or(SddlError::Truncated("sid"))?).ok_or(SddlError::BadSid)
}

/// Parse a self-relative `SECURITY_DESCRIPTOR`. Offsets are from the start of `b`. Never panics
/// on malformed / hostile input — returns [`SddlError`] instead.
pub fn parse(b: &[u8]) -> Result<SecurityDescriptor> {
    if b.len() < 20 {
        return Err(SddlError::Truncated("sd header"));
    }
    let control = u16le(b, 2)?;
    if control & SE_SELF_RELATIVE == 0 {
        return Err(SddlError::Malformed("SE_SELF_RELATIVE is not set"));
    }
    let owner_off = u32le(b, 4)? as usize;
    let group_off = u32le(b, 8)? as usize;
    let dacl_off = u32le(b, 16)? as usize;

    let owner = (owner_off != 0).then(|| sid_at(b, owner_off)).transpose()?;
    let group = (group_off != 0).then(|| sid_at(b, group_off)).transpose()?;
    let (dacl_kind, dacl) = match (control & SE_DACL_PRESENT != 0, dacl_off) {
        (false, 0) => (DaclKind::NotPresent, None),
        (false, _) => {
            return Err(SddlError::Malformed(
                "DACL offset is non-zero while SE_DACL_PRESENT is clear",
            ))
        }
        (true, 0) => (DaclKind::Null, None),
        (true, _) => (DaclKind::Present, Some(parse_acl(b, dacl_off)?)),
    };

    Ok(SecurityDescriptor {
        control,
        owner,
        group,
        dacl_kind,
        dacl,
    })
}

fn parse_acl(b: &[u8], off: usize) -> Result<Acl> {
    // ACL header: Revision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
    let acl_size = u16le(
        b,
        off.checked_add(2)
            .ok_or(SddlError::Malformed("ACL offset overflow"))?,
    )? as usize;
    if acl_size < 8 {
        return Err(SddlError::Malformed(
            "AclSize is smaller than the ACL header",
        ));
    }
    let acl_end = off
        .checked_add(acl_size)
        .ok_or(SddlError::Malformed("AclSize overflow"))?;
    if acl_end > b.len() {
        return Err(SddlError::Truncated("acl"));
    }
    let ace_count = u16le(b, off + 4)? as usize;
    if ace_count > (acl_size - 8) / 4 {
        return Err(SddlError::Malformed("AceCount cannot fit in AclSize"));
    }
    let mut cur = off + 8;
    let mut aces = Vec::with_capacity(ace_count);
    for _ in 0..ace_count {
        let header_end = cur
            .checked_add(4)
            .ok_or(SddlError::Malformed("ACE header overflow"))?;
        if header_end > acl_end {
            return Err(SddlError::Truncated("ace header"));
        }
        let size = u16le(b, cur + 2)? as usize;
        if size < 8 {
            return Err(SddlError::Malformed(
                "AceSize is smaller than the ACE header and mask",
            ));
        }
        let ace_end = cur
            .checked_add(size)
            .ok_or(SddlError::Malformed("AceSize overflow"))?;
        if ace_end > acl_end {
            return Err(SddlError::Malformed("ACE escapes AclSize"));
        }
        let ace = &b[cur..ace_end];
        let ace_type_byte = ace[0];
        let flags = ace[1];
        let ace_type = match ace_type_byte {
            0x00 => AceType::AccessAllowed,
            0x01 => AceType::AccessDenied,
            0x05 => AceType::AccessAllowedObject,
            0x06 => AceType::AccessDeniedObject,
            x => AceType::Other(x),
        };
        let mask = AccessMask::from_bits_truncate(u32le(ace, 4)?);

        let (object_type, inherited_object_type, sid_off) = match ace_type {
            AceType::AccessAllowedObject | AceType::AccessDeniedObject => {
                // Mask(4) Flags(4) [ObjectType 16] [InheritedObjectType 16] Sid
                if size < 12 {
                    return Err(SddlError::Malformed(
                        "object ACE is smaller than its fixed fields",
                    ));
                }
                let obj_flags = u32le(ace, 8)?;
                let mut p = 12;
                let mut ot = None;
                let mut iot = None;
                if obj_flags & 0x1 != 0 {
                    ot = ace.get(p..p + 16).and_then(Guid::from_bytes);
                    if ot.is_none() {
                        return Err(SddlError::Truncated("object ACE ObjectType GUID"));
                    }
                    p += 16;
                }
                if obj_flags & 0x2 != 0 {
                    iot = ace.get(p..p + 16).and_then(Guid::from_bytes);
                    if iot.is_none() {
                        return Err(SddlError::Truncated("object ACE InheritedObjectType GUID"));
                    }
                    p += 16;
                }
                (ot, iot, p)
            }
            _ => (None, None, 8),
        };

        let trustee = sid_at(ace, sid_off)?;
        aces.push(Ace {
            ace_type,
            flags,
            mask,
            trustee,
            object_type,
            inherited_object_type,
        });
        cur = ace_end;
    }
    if cur != acl_end {
        return Err(SddlError::Malformed(
            "AclSize contains bytes not described by AceCount",
        ));
    }
    Ok(Acl { aces })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rbcd_sd_roundtrips_through_parser() {
        let sid = Sid::parse("S-1-5-21-1-2-3-1104").unwrap();
        let sd = build_rbcd_sd(&sid);
        let parsed = parse(&sd).expect("parse our own SD");
        let aces = &parsed.dacl.expect("dacl").aces;
        assert_eq!(aces.len(), 1);
        assert!(aces[0].is_allow());
        assert_eq!(aces[0].trustee, sid);
        assert!(aces[0].mask.contains(AccessMask::WRITE_DAC));
    }

    /// A truncated object-ACE (ObjectType flag set, no GUID bytes) must not panic.
    #[test]
    fn truncated_object_ace_does_not_panic() {
        let mut sd = vec![1, 0, 0x04, 0x80];
        sd.extend_from_slice(&0u32.to_le_bytes()); // owner off
        sd.extend_from_slice(&0u32.to_le_bytes()); // group off
        sd.extend_from_slice(&0u32.to_le_bytes()); // sacl off
        sd.extend_from_slice(&20u32.to_le_bytes()); // dacl off
        sd.extend_from_slice(&[2, 0, 0x30, 0, 1, 0, 0, 0]); // ACL hdr: 1 ACE
        sd.extend_from_slice(&[0x05, 0, 0x20, 0]); // AccessAllowedObject, size 0x20
        sd.extend_from_slice(&0u32.to_le_bytes()); // mask
        sd.extend_from_slice(&1u32.to_le_bytes()); // obj_flags = ObjectType present, no GUID follows
        let _ = parse(&sd); // must not panic
    }

    #[test]
    fn null_dacl_is_distinct_from_absent_dacl() {
        let mut null_sd = vec![1, 0];
        null_sd.extend_from_slice(&0x8004u16.to_le_bytes());
        null_sd.extend_from_slice(&[0u8; 16]);
        let parsed = parse(&null_sd).expect("NULL DACL descriptor");
        assert_eq!(parsed.dacl_kind, DaclKind::Null);
        assert!(parsed.dacl.is_none());

        let mut absent_sd = vec![1, 0];
        absent_sd.extend_from_slice(&0x8000u16.to_le_bytes());
        absent_sd.extend_from_slice(&[0u8; 16]);
        let parsed = parse(&absent_sd).expect("absent DACL descriptor");
        assert_eq!(parsed.dacl_kind, DaclKind::NotPresent);
        assert!(parsed.dacl.is_none());
    }

    #[test]
    fn rejects_ace_that_escapes_declared_acl() {
        let sid = Sid::parse("S-1-5-21-1-2-3-1104").unwrap();
        let mut sd = build_rbcd_sd(&sid);
        let dacl_off = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        sd[dacl_off + 2..dacl_off + 4].copy_from_slice(&8u16.to_le_bytes());
        assert!(parse(&sd).is_err());
    }

    #[test]
    fn rejects_zero_sized_ace_instead_of_returning_partial_acl() {
        let sid = Sid::parse("S-1-5-21-1-2-3-1104").unwrap();
        let mut sd = build_rbcd_sd(&sid);
        let dacl_off = u32::from_le_bytes(sd[16..20].try_into().unwrap()) as usize;
        sd[dacl_off + 10..dacl_off + 12].copy_from_slice(&0u16.to_le_bytes());
        assert!(parse(&sd).is_err());
    }

    /// Fuzz-lite: random + seed-mutated bytes must never panic (deterministic seed).
    #[test]
    fn fuzz_parse_never_panics() {
        let mut seed = vec![1, 0, 0x04, 0x80];
        seed.extend_from_slice(&0u32.to_le_bytes());
        seed.extend_from_slice(&0u32.to_le_bytes());
        seed.extend_from_slice(&0u32.to_le_bytes());
        seed.extend_from_slice(&20u32.to_le_bytes());
        seed.extend_from_slice(&[2, 0, 0x30, 0, 1, 0, 0, 0]);
        seed.extend_from_slice(&[0x05, 0, 0x2c, 0]);
        seed.extend_from_slice(&[0u8; 40]);

        let mut s: u64 = 0xDEAD_BEEF_CAFE_F00D;
        let mut rng = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let mut fail = None;
        for _ in 0..200_000 {
            let mut buf = if rng() & 1 == 0 {
                seed.clone()
            } else {
                let n = (rng() as usize) % 80;
                (0..n).map(|_| rng() as u8).collect::<Vec<u8>>()
            };
            for _ in 0..(rng() as usize % 6) {
                if !buf.is_empty() {
                    let i = (rng() as usize) % buf.len();
                    buf[i] = rng() as u8;
                }
            }
            let b = buf.clone();
            if std::panic::catch_unwind(|| {
                let _ = parse(&b);
            })
            .is_err()
            {
                fail = Some(buf);
                break;
            }
        }
        std::panic::set_hook(prev);
        if let Some(buf) = fail {
            panic!(
                "parse panicked on {} bytes: {}",
                buf.len(),
                buf.iter().map(|x| format!("{x:02x}")).collect::<String>()
            );
        }
    }
}
