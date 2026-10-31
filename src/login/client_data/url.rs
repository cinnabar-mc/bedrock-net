// SPDX-License-Identifier: MIT
//! Shared URL host decoding for the actual relay origin and title metadata consumers.
//! Source-attributed Go net/url host escape rules; see NOTICE.

/// Decodes HTTP(S) URL host/optional-port spelling without DNS, origin or egress approval.
/// Hosts retain escaped bytes even when they are not UTF-8.
/// Bracketed IP-literal validation remains with the concrete consumer; no input grants authority.
pub fn decode_url_host(host: &str) -> Option<Vec<u8>> {
    if let Some(literal) = host.strip_prefix('[') {
        let (literal, port) = literal.rsplit_once(']')?;
        if !optional_port(port) {
            return None;
        }
        let decoded = match literal.find("%25") {
            Some(index) => {
                let mut decoded = unescape(&literal[..index], Escape::Host)?;
                decoded.extend(unescape(&literal[index..], Escape::Zone)?);
                decoded
            }
            None => unescape(literal, Escape::Host)?,
        };
        let mut result = vec![b'['];
        result.extend(decoded);
        result.push(b']');
        result.extend_from_slice(port.as_bytes());
        return Some(result);
    }
    if host.contains('[') {
        return None;
    }
    if let Some((_, port)) = host.split_once(':')
        && !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    unescape(host, Escape::Host)
}

#[derive(Clone, Copy)]
enum Escape {
    Host,
    Zone,
}

/// A present port may be empty but otherwise contains only decimal digits, without range rewriting.
fn optional_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Decodes host escapes and the IPv6 zone exception while rejecting control/authority delimiters.
fn unescape(raw: &str, mode: Escape) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = char::from(bytes.next()?).to_digit(16)?;
            let low = char::from(bytes.next()?).to_digit(16)?;
            let decoded = u8::try_from(high * 16 + low).ok()?;
            if decoded != b'%'
                && if matches!(mode, Escape::Zone) {
                    decoded != b' ' && !host_byte(decoded)
                } else {
                    decoded.is_ascii()
                }
            {
                return None;
            }
            result.push(decoded);
        } else {
            if byte.is_ascii() && !host_byte(byte) {
                return None;
            }
            result.push(byte);
        }
    }
    Some(result)
}

/// URL host characters, including Go's retained host sub-delimiters; not a DNS allowlist.
fn host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_'
                | b'.'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'['
                | b']'
                | b'<'
                | b'>'
                | b'"'
        )
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_escapes_preserve_non_utf8_bytes() {
        for (input, expected) in [
            ("[::1]", b"[::1]".as_slice()),
            ("[2001:db8::1]:123", b"[2001:db8::1]:123"),
            ("example%FF.com", b"example\xff.com".as_slice()),
            ("%C3", b"\xc3"),
            ("%C3%A9", b"\xc3\xa9"),
        ] {
            assert_eq!(
                super::decode_url_host(input).map(|host| host.to_vec()),
                Some(expected.to_vec())
            );
        }
        for host in [
            "::1",
            "2001:db8::1",
            "a[b",
            "example%2f.com",
            "::bad",
            "host:no",
            "[::1]bad",
        ] {
            assert!(super::decode_url_host(host).is_none(), "{host}");
        }
    }
}
