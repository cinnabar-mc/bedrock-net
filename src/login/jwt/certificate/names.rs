//! Interpreted certificate names; no hostname, mailbox or URI is authorized by these checks.

use super::super::url;
use super::der;

/// Traverses issuer/subject RDN sets and interprets only each attribute's OID and first value.
pub(super) fn distinguished(mut data: &[u8]) -> Option<()> {
    while !data.is_empty() {
        let mut set = der::take(&mut data, 0x31)?;
        while !set.is_empty() {
            let mut attribute = der::take(&mut set, 0x30)?;
            der::oid(der::take(&mut attribute, 6)?, true)?;
            let (tag, value) = der::any(&mut attribute)?;
            let valid = match tag {
                0x14 => true, // Every T61 octet is interpreted as Latin-1.
                0x13 => value
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?*&".contains(b)),
                0x0c => std::str::from_utf8(value).is_ok(),
                0x1e => {
                    let (points, tail) = value.as_chunks::<2>();
                    tail.is_empty()
                        && points.iter().all(|pair| {
                            let point = u16::from_be_bytes(*pair);
                            !matches!(point, 0xd800..=0xdfff | 0xfdd0..=0xfdef | 0xfffe..=0xffff)
                        })
                }
                0x16 => value.is_ascii(),
                0x12 => value.iter().all(|b| b.is_ascii_digit() || *b == b' '),
                _ => false,
            };
            if !valid {
                return None;
            }
        }
    }
    Some(())
}

/// Checks only recognized SAN tags, including IA5, IP widths and URI-reference host semantics.
pub(super) fn san(value: &[u8]) -> Option<()> {
    let mut data = value;
    let mut names = der::take(&mut data, 0x30)?;
    while !names.is_empty() {
        let (tag, name) = der::any(&mut names)?;
        match tag {
            0x81 | 0x82 => {
                ascii(name)?;
            }
            0x86 => {
                let host = url::parse(ascii(name)?)?;
                if !domain(&host, false) {
                    return None;
                }
            }
            0x87 if !matches!(name.len(), 4 | 16) => return None,
            _ => {}
        }
    }
    Some(())
}

/// Checks permitted/excluded subtree framing and the four name types the decoder interprets.
pub(super) fn constraints(value: &[u8]) -> Option<()> {
    let mut data = value;
    let mut sequence = der::take(&mut data, 0x30)?;
    if !data.is_empty() {
        return None;
    }
    let mut present = false;
    for tag in [0xa0, 0xa1] {
        if sequence.first() != Some(&tag) {
            continue;
        }
        let mut trees = der::take(&mut sequence, tag)?;
        present |= !trees.is_empty();
        while !trees.is_empty() {
            let mut tree = der::take(&mut trees, 0x30)?;
            let (tag, name) = der::any(&mut tree)?;
            match tag {
                0x81 => {
                    let text = ascii(name)?;
                    if if name.contains(&b'@') {
                        !mailbox(name)
                    } else {
                        !domain(text.as_bytes(), true)
                    } {
                        return None;
                    }
                }
                0x82 | 0x86 => {
                    let text = ascii(name)?;
                    if !domain(name, true)
                        || (tag == 0x86 && text.parse::<std::net::IpAddr>().is_ok())
                    {
                        return None;
                    }
                }
                0x87 if !matches!(name.len(), 8 | 32) || !mask(&name[name.len() / 2..]) => {
                    return None;
                }
                _ => {}
            }
        }
    }
    (present && sequence.is_empty()).then_some(())
}

/// Accepts every IA5 byte, including controls; concrete URI/domain consumers add their own rules.
fn ascii(value: &[u8]) -> Option<&str> {
    value
        .is_ascii()
        .then(|| std::str::from_utf8(value).expect("ASCII"))
}

/// Matches the decoder's printable nonempty labels, allowing a leading dot only in constraints.
fn domain(value: &[u8], constraint: bool) -> bool {
    if value.is_empty() {
        return true;
    }
    let value = if constraint && value[0] == b'.' {
        &value[1..]
    } else {
        value
    };
    value.iter().all(|b| (33..=126).contains(b))
        && value.split(|b| *b == b'.').all(|label| !label.is_empty())
}

/// Requires a contiguous IP mask, without imposing a normalized network address.
fn mask(value: &[u8]) -> bool {
    let mut zero = false;
    for byte in value {
        for bit in (0..8).rev() {
            let one = byte & (1 << bit) != 0;
            if zero && one {
                return false;
            }
            zero |= !one;
        }
    }
    true
}

/// Checks mailbox constraints with the decoder's quoted-string and escaped-atom allowances.
fn mailbox(mut value: &[u8]) -> bool {
    let mut local = Vec::new();
    if value.first() == Some(&b'"') {
        value = &value[1..];
        loop {
            let Some((&byte, rest)) = value.split_first() else {
                return false;
            };
            value = rest;
            match byte {
                b'"' => break,
                b'\\' => {
                    let Some((&byte, rest)) = value.split_first() else {
                        return false;
                    };
                    if byte == 0 || matches!(byte, 10 | 13) || byte > 127 {
                        return false;
                    }
                    local.push(byte);
                    value = rest;
                }
                1..=8 | 11..=12 | 14..=127 => local.push(byte),
                _ => return false,
            }
        }
    } else {
        while let Some((&byte, rest)) = value.split_first() {
            if byte == b'\\' {
                let Some((&byte, rest)) = rest.split_first() else {
                    return false;
                };
                local.push(byte);
                value = rest;
            } else if byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&byte) {
                local.push(byte);
                value = rest;
            } else {
                break;
            }
        }
        if local.is_empty()
            || local.first() == Some(&b'.')
            || local.last() == Some(&b'.')
            || local.windows(2).any(|pair| pair == b"..")
        {
            return false;
        }
    }
    let Some(domain) = value.strip_prefix(b"@") else {
        return false;
    };
    // Mailbox domains use the same printable-label rule but permit the empty spelling.
    self::domain(domain, false)
}
