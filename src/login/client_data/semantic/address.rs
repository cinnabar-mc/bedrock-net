// SPDX-License-Identifier: MIT
//! Incoming address syntax is metadata only; DNS and OS service resolution are deliberately omitted.
//! URL component admission follows the actual Go net/url consumer, without browser normalization.

/// Checks shape only; the actual selected target and socket supply the final signed `ServerAddress`.
pub(super) fn valid(address: &str) -> bool {
    if address.contains("://") {
        return crate::login::url::server_address(address);
    }
    if !address.contains(':') {
        // The original consumer ignores resolution errors when no colon exists.
        return true;
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.contains(['[', ']']) {
        return false;
    }
    if let Some(host) = host.strip_prefix('[') {
        let Some(host) = host.strip_suffix(']') else {
            return false;
        };
        if host.contains(['[', ']']) {
            return false;
        }
    } else if host.contains([':', '[', ']']) {
        return false;
    }
    port_syntax(port)
}

/// Preserves empty/signed numeric zero; named service lookup is part of the explicit resolution gap.
fn port_syntax(port: &str) -> bool {
    let (digits, negative) = if let Some(value) = port.strip_prefix('-') {
        (value, true)
    } else {
        (port.strip_prefix('+').unwrap_or(port), false)
    };
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    if digits.is_empty() {
        return true;
    }
    digits
        .parse::<u16>()
        .is_ok_and(|value| !negative || value == 0)
}
