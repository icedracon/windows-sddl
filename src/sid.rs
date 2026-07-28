//! SID / GUID types per MS-DTYP. No FFI — pure binary + string handling, so this works
//! cross-platform against raw bytes (LDAP `objectSid`, registry hives, backup formats).

use std::fmt;

/// Windows Security Identifier. Stored canonically; `Display` yields `S-1-5-...`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    /// 6-byte identifier authority (big-endian on the wire).
    pub identifier_authority: u64,
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Parse the binary (`objectSid` / `SID_AND_ATTRIBUTES`) representation.
    pub fn from_bytes(b: &[u8]) -> Option<Sid> {
        if b.len() < 8 {
            return None;
        }
        let revision = b[0];
        let count = b[1] as usize;
        let mut authority: u64 = 0;
        for &byte in &b[2..8] {
            authority = (authority << 8) | byte as u64; // big-endian
        }
        if b.len() < 8 + count * 4 {
            return None;
        }
        let mut subs = Vec::with_capacity(count);
        for i in 0..count {
            let off = 8 + i * 4;
            subs.push(u32::from_le_bytes([
                b[off],
                b[off + 1],
                b[off + 2],
                b[off + 3],
            ]));
        }
        Some(Sid {
            revision,
            identifier_authority: authority,
            sub_authorities: subs,
        })
    }

    /// Serialize to the binary (`objectSid`) form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![self.revision, self.sub_authorities.len() as u8];
        let a = self.identifier_authority;
        b.extend_from_slice(&[
            (a >> 40) as u8,
            (a >> 32) as u8,
            (a >> 24) as u8,
            (a >> 16) as u8,
            (a >> 8) as u8,
            a as u8,
        ]);
        for s in &self.sub_authorities {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    /// Parse the string form `S-1-5-21-...-513`.
    pub fn parse(s: &str) -> Option<Sid> {
        let mut it = s.split('-');
        if it.next()? != "S" {
            return None;
        }
        let revision = it.next()?.parse().ok()?;
        let identifier_authority = it.next()?.parse().ok()?;
        let sub_authorities = it.map(|p| p.parse().ok()).collect::<Option<Vec<u32>>>()?;
        Some(Sid {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }

    /// Last sub-authority — the RID.
    pub fn rid(&self) -> Option<u32> {
        self.sub_authorities.last().copied()
    }

    /// True for built-in / well-known SIDs that are never domain-specific (e.g. `S-1-5-32-544`).
    pub fn is_well_known(&self) -> bool {
        matches!(self.identifier_authority, 1 | 3) // WORLD, CREATOR
            || (self.identifier_authority == 5 && self.sub_authorities.first() == Some(&32))
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.identifier_authority)?;
        for s in &self.sub_authorities {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 16-byte GUID stored in the mixed-endian on-wire layout, normalized to a comparable byte
/// array. Rendered `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub fn from_bytes(b: &[u8]) -> Option<Guid> {
        Some(Guid(b.get(..16)?.try_into().ok()?))
    }

    /// Parse `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (braces optional).
    pub fn parse(s: &str) -> Option<Guid> {
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return None;
        }
        let raw: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
            .collect::<Option<_>>()?;
        // string form is big-endian for the first 3 groups; store normalized for comparison.
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
        b[4..6].copy_from_slice(&[raw[5], raw[4]]);
        b[6..8].copy_from_slice(&[raw[7], raw[6]]);
        b[8..16].copy_from_slice(&raw[8..16]);
        Some(Guid(b))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_roundtrip_string_and_bytes() {
        let s = Sid::parse("S-1-5-21-1-2-3-1104").unwrap();
        assert_eq!(s.rid(), Some(1104));
        assert_eq!(s.to_string(), "S-1-5-21-1-2-3-1104");
        let bytes = s.to_bytes();
        assert_eq!(Sid::from_bytes(&bytes).unwrap(), s);
    }

    #[test]
    fn guid_parse_display_roundtrip() {
        let g = Guid::parse("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2").unwrap();
        assert_eq!(g.to_string(), "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
    }
}
