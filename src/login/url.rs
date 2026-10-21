//! Go URL-reference admission for auxiliary JOSE data; no address is fetched or authorized.
// Source-attributed Go net/url syntax; see NOTICE and LICENSE-BSD-Go.

/// Returns the decoded host bytes for certificate URI checks, retaining relative and opaque forms.
pub(super) fn parse(value: &str) -> Option<Vec<u8>> {
    let (main, fragment) = value
        .split_once('#')
        .map_or((value, None), |(m, f)| (m, Some(f)));
    if fragment.is_some_and(|f| !escaped(f)) || main.bytes().any(|b| b < 32 || b == 127) {
        return None;
    }
    let main = main.split_once('?').map_or(main, |(m, _)| m);
    let mut scheme = "";
    let mut rest = main;
    if let Some((prefix, suffix)) = main.split_once(':')
        && !prefix.contains('/')
    {
        if prefix.is_empty()
            || !prefix.as_bytes()[0].is_ascii_alphabetic()
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
        {
            return None;
        }
        scheme = prefix;
        rest = suffix;
        if !rest.starts_with('/') {
            return Some(Vec::new());
        }
    }
    if !rest.starts_with("//") || (scheme.is_empty() && rest.starts_with("///")) {
        return escaped(rest).then(Vec::new);
    }
    let (authority, path) = rest[2..].split_once('/').unwrap_or((&rest[2..], ""));
    if !escaped(path) {
        return None;
    }
    let host = if let Some((user, host)) = authority.rsplit_once('@') {
        if !escaped(user)
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._:~!$&'()*+,;=%@".contains(&b))
        {
            return None;
        }
        host
    } else {
        authority
    };
    host_bytes(host, scheme)
}

/// Decodes host and zone escapes as bytes, applying IP-literal and optional-port syntax only.
fn host_bytes(host: &str, scheme: &str) -> Option<Vec<u8>> {
    if host.rfind('[').is_some_and(|n| n > 0) {
        return None;
    }
    if let Some(literal) = host.strip_prefix('[') {
        let (literal, port) = literal.rsplit_once(']')?;
        if !optional_port(port) {
            return None;
        }
        let decoded = if let Some(n) = literal.find("%25") {
            let mut value = unescape(&literal[..n], false)?;
            value.extend(unescape(&literal[n..], true)?);
            value
        } else {
            unescape(literal, false)?
        };
        let split = decoded
            .iter()
            .position(|b| *b == b'%')
            .unwrap_or(decoded.len());
        let ip = std::str::from_utf8(&decoded[..split]).ok()?;
        ip.parse::<std::net::Ipv6Addr>().ok()?;
        if split < decoded.len() && split + 1 == decoded.len() {
            return None;
        }
        let mut result = vec![b'['];
        result.extend(decoded);
        result.push(b']');
        result.extend_from_slice(port.as_bytes());
        return Some(result);
    }
    if let Some(first) = host.find(':') {
        let index = if scheme.eq_ignore_ascii_case("postgres")
            || scheme.eq_ignore_ascii_case("postgresql")
        {
            host.rfind(':')?
        } else {
            first
        };
        if !optional_port(&host[index..]) {
            return None;
        }
    }
    unescape(host, false)
}

/// A URL port may be absent or empty, and otherwise consists only of decimal digits.
fn optional_port(value: &str) -> bool {
    value.is_empty()
        || value
            .strip_prefix(':')
            .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()))
}

/// Decodes only the percent escapes allowed in host or scoped-zone positions, without UTF-8 checks.
fn unescape(value: &str, zone: bool) -> Option<Vec<u8>> {
    let mut input = value.bytes();
    let mut output = Vec::with_capacity(value.len());
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = char::from(input.next()?).to_digit(16)?;
            let low = char::from(input.next()?).to_digit(16)?;
            let byte = (high * 16 + low) as u8;
            if byte != b'%'
                && if zone {
                    byte != b' ' && !host_byte(byte)
                } else {
                    byte < 128
                }
            {
                return None;
            }
            output.push(byte);
        } else {
            if byte < 128 && !host_byte(byte) {
                return None;
            }
            output.push(byte);
        }
    }
    Some(output)
}

/// Go retains host sub-delimiters in auxiliary references, independently of DNS or transport policy.
fn host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&byte)
}

/// Checks percent triplets without imposing fragment control-byte or query escape restrictions.
fn escaped(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                && bytes.next().is_some_and(|b| b.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    true
}
