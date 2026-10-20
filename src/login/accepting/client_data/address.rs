//! Address syntax checks for the pure accepting verifier, without DNS or service lookups.
// Copyright 2009 The Go Authors. All rights reserved.
// Address parsing follows Go's BSD-licensed net and net/url packages; see LICENSE-GO.

use std::net::{IpAddr, Ipv6Addr};

/// Checks pure syntax and identifies the normalized UDP address that still needs resolution.
pub(super) fn resolution(address: &str) -> Option<Option<String>> {
    if address.contains("://") {
        return valid_url(address).then_some(None);
    }
    if !address.contains(':') {
        return Some(None);
    }
    let normalized =
        if !address.starts_with('[') && address.bytes().filter(|b| *b == b':').count() > 1 {
            let (host, port) = address.rsplit_once(':')?;
            format!("[{host}]:{port}")
        } else {
            address.to_owned()
        };
    let (host, port) = normalized.rsplit_once(':')?;
    let host = if host.starts_with('[') {
        host.strip_prefix('[')?.strip_suffix(']')?
    } else {
        host
    };
    if host.contains(['[', ']']) || port.contains(['[', ']']) {
        return None;
    }
    let literal = if host.is_empty() {
        true
    } else if host.contains(':') {
        let (ip, zone) = host
            .split_once('%')
            .map_or((host, None), |(ip, zone)| (ip, Some(zone)));
        // Go falls back to its configured resolver for non-literals and empty zones.
        ip.parse::<Ipv6Addr>().is_ok() && zone != Some("")
    } else {
        host.parse::<IpAddr>().is_ok()
    };
    let (negative, digits) = if let Some(s) = port.strip_prefix('-') {
        (true, s)
    } else {
        (false, port.strip_prefix('+').unwrap_or(port))
    };
    let mut number = 0u32;
    let mut lookup = false;
    for b in digits.bytes() {
        if !b.is_ascii_digit() {
            lookup = true;
            break;
        }
        if number >= 1 << 30 {
            number = u32::MAX;
            break;
        }
        number = number.wrapping_mul(10);
        let next = number.wrapping_add(u32::from(b - b'0'));
        if next < number {
            number = u32::MAX;
            break;
        }
        number = next;
    }
    if !lookup && (number > 65535 || (negative && number != 0)) {
        return None;
    }
    Some(if literal && !lookup {
        None
    } else {
        Some(normalized)
    })
}

/// Checks Go URL host escaping and returns decoded bytes without WHATWG repairs.
fn unescape(value: &str, host: bool, zone: bool) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let escaped = bytes.get(i + 1..i + 3)?;
            if !escaped.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let n = u8::from_str_radix(std::str::from_utf8(escaped).ok()?, 16).ok()?;
            if host && n < 128 && n != b'%' {
                return None;
            }
            if zone && n != b'%' && n != b' ' && !host_byte(n) {
                return None;
            }
            result.push(n);
            i += 3;
        } else {
            if (host || zone) && !host_byte(b) {
                return None;
            }
            result.push(b);
            i += 1;
        }
    }
    Some(result)
}

/// Recognizes net/url's unescaped host-byte set, including opaque non-ASCII bytes.
fn host_byte(b: u8) -> bool {
    b >= 128 || b.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&b)
}

/// Applies net/url syntax and the baseline's scheme, host and duplicated-port checks.
fn valid_url(address: &str) -> bool {
    let Some((inner, outer_port)) = address.rsplit_once(':') else {
        return false;
    };
    if inner.bytes().any(|b| b < 32 || b == 127) {
        return false;
    }
    let Some((scheme, rest)) = inner.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let (rest, fragment) = rest
        .split_once('#')
        .map_or((rest, None), |(r, f)| (r, Some(f)));
    if fragment.is_some_and(|f| unescape(f, false, false).is_none()) {
        return false;
    }
    let rest = rest.split_once('?').map_or(rest, |(r, _)| r);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if unescape(path, false, false).is_none() {
        return false;
    }
    let host = if let Some((user, host)) = authority.rsplit_once('@') {
        if !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&b))
            || unescape(user, false, false).is_none()
        {
            return false;
        }
        host
    } else {
        authority
    };
    let Some((hostname, port)) = host.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) || port != outer_port {
        return false;
    }
    if hostname.starts_with('[') {
        let Some(ip) = hostname.strip_prefix('[').and_then(|h| h.strip_suffix(']')) else {
            return false;
        };
        let (ip, zone) = ip
            .split_once("%25")
            .map_or((ip, None), |(ip, z)| (ip, Some(z)));
        if unescape(ip, true, false).is_none()
            || zone.is_some_and(|z| z.is_empty() || unescape(z, false, true).is_none())
        {
            return false;
        }
        ip.parse::<Ipv6Addr>().is_ok()
    } else {
        !hostname.contains(':')
            && !hostname.contains('[')
            && unescape(hostname, true, false).is_some()
    }
}
