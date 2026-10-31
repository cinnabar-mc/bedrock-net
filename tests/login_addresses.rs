//! Login return-address parsing without transport discovery or DNS.
#![cfg(feature = "login")]

use bedrock_net::login::split_server_address;

#[test]
fn split_server_address_accepts_current_legacy_and_plain_targets() {
    for (address, host, port) in [
        ("play.example.com:19132", &b"play.example.com"[..], 19132),
        ("[::1]:19133", &b"::1"[..], 19133),
        ("http://127.0.0.1:19132", &b"127.0.0.1"[..], 19132),
        ("http://127.0.0.1:19132:19132", &b"127.0.0.1"[..], 19132),
        (
            "https://play.example.com:443:443",
            &b"play.example.com"[..],
            443,
        ),
        ("https://[::1]:19133", &b"::1"[..], 19133),
        (
            "https://[fe80::1%25eth0]:19132",
            &b"fe80::1%eth0"[..],
            19132,
        ),
        (
            "http://user:pass@host:00080/path?query#fragment",
            &b"host"[..],
            80,
        ),
        ("ftp://host:21", &b"host"[..], 21),
        ("http://ho%ffst:19132:19132", &b"ho\xffst"[..], 19132),
        ("[named-host]:7", &b"named-host"[..], 7),
    ] {
        assert_eq!(
            split_server_address(address),
            Some((host.to_vec(), port)),
            "{address}"
        );
    }
}

#[test]
fn split_server_address_has_no_return_target_for_lan_or_invalid_ports() {
    for address in [
        ":0",
        "",
        "host",
        "host:0",
        "host:",
        "host:65536",
        "host:+1",
        "host:-1",
        "https://host",
        "https://host:1:2",
        "http://:19132",
        "host:1:1",
        "[::1]",
        "http://[invalid]:19132",
        "https://host:1/#bad%zz",
    ] {
        assert_eq!(split_server_address(address), None, "{address}");
    }
}
