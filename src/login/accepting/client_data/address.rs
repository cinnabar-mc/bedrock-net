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

/// Adds the metadata owner's HTTP scheme, IPv6 and duplicated-port requirements to Go URL syntax.
fn valid_url(address: &str) -> bool {
    let Some((inner, outer_port)) = address.rsplit_once(':') else {
        return false;
    };
    if inner.bytes().any(|byte| byte < 32 || byte == 127) {
        return false;
    }
    let Some((scheme, _)) = inner.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let Some(host) = crate::login::url::parse(inner) else {
        return false;
    };
    let Some(colon) = host.iter().rposition(|byte| *byte == b':') else {
        return false;
    };
    let (hostname, port) = (&host[..colon], &host[colon + 1..]);
    if port.is_empty() || !port.iter().all(u8::is_ascii_digit) || port != outer_port.as_bytes() {
        return false;
    }
    if hostname.starts_with(b"[") {
        let Some(ip) = hostname
            .strip_prefix(b"[")
            .and_then(|ip| ip.strip_suffix(b"]"))
        else {
            return false;
        };
        let (ip, zone) = ip
            .iter()
            .position(|byte| *byte == b'%')
            .map_or((ip, None), |index| (&ip[..index], Some(&ip[index + 1..])));
        zone != Some(b"".as_slice())
            && std::str::from_utf8(ip)
                .ok()
                .is_some_and(|ip| ip.parse::<Ipv6Addr>().is_ok())
    } else {
        !hostname.contains(&b':') && !hostname.contains(&b'[')
    }
}
