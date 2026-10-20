// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Bounded server transfer targets; following a target remains caller policy.

use bedrock_protocol::packets;

/// Longest retained transfer host, in bytes.
///
/// DNS names cap at 253 octets and literal IPv6 at 45 characters, so this
/// bounds every legitimate target while refusing unbounded wire strings.
pub const MAX_TRANSFER_HOST_BYTES: usize = 255;

/// Bounded record of a server-directed transfer target.
///
/// The host is trimmed and checked for well-formedness only; following it is a policy
/// decision above the protocol layer; unrelated target hosts are permitted.
/// The optional gatherings configuration is not retained: nothing consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTarget {
    /// Trimmed server-supplied host, retained without resolving or following it.
    pub host: String,
    /// Nonzero destination port supplied by the server.
    pub port: u16,
    /// Server request to reload world state when following this target.
    pub reload_world: bool,
}

/// Why a completely decoded Transfer packet named an unusable target.
///
/// These are semantic oddities, not wire failures: the session survives and the
/// caller counts the rejection instead of tearing down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferRejection {
    /// No host remains after trimming surrounding whitespace.
    EmptyHost,
    /// The trimmed host exceeds the retained byte bound.
    HostTooLong {
        /// Actual trimmed host size, without truncation.
        bytes: usize,
    },
    /// The host contains a control character or interior ASCII space.
    InvalidHostCharacter,
    /// The destination port cannot address a remote endpoint.
    ZeroPort,
}

impl TransferTarget {
    /// Normalizes one decoded packet; other packets normalize to nothing.
    pub fn from_packet_data(data: &packets::Packet) -> Result<Option<Self>, TransferRejection> {
        let packets::Packet::Transfer(packet) = data else {
            return Ok(None);
        };
        Self::from_target(
            &packet.server_address.to_string_lossy(),
            packet.server_port.0,
            packet.reload_world,
        )
        .map(Some)
    }

    /// Validates a destination, from a generated packet or an already decoded transfer, before it is kept.
    pub fn from_target(
        address: &str,
        port: u16,
        reload_world: bool,
    ) -> Result<Self, TransferRejection> {
        let host = address.trim();
        if host.is_empty() {
            return Err(TransferRejection::EmptyHost);
        }
        if host.len() > MAX_TRANSFER_HOST_BYTES {
            return Err(TransferRejection::HostTooLong { bytes: host.len() });
        }
        if host.chars().any(is_forbidden_host_character) {
            return Err(TransferRejection::InvalidHostCharacter);
        }
        if port == 0 {
            return Err(TransferRejection::ZeroPort);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            reload_world,
        })
    }
}

/// Rejects ASCII control characters and interior spaces: a well-formedness floor, not a
/// hostname grammar, so unusual but dialable hosts fail visibly when dialled instead.
fn is_forbidden_host_character(character: char) -> bool {
    matches!(character, '\0'..='\x1f' | '\x7f' | ' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_protocol::packets::Transfer;
    use bedrock_protocol::wire;

    fn transfer_data(address: &str, port: u16) -> packets::Packet {
        packets::Packet::Transfer(Transfer {
            server_address: address.into(),
            server_port: wire::U16LE(port),
            reload_world: false,
            ..Default::default()
        })
    }

    #[test]
    fn normalization_retains_a_bounded_target() {
        let event = TransferTarget::from_packet_data(&transfer_data("play.example.net", 19133))
            .expect("well-formed target")
            .expect("transfer packet normalizes");
        assert_eq!(event.host, "play.example.net");
        assert_eq!(event.port, 19133);
        assert!(!event.reload_world);
    }

    #[test]
    fn normalization_retains_the_reload_flag_and_trims_surrounding_whitespace() {
        let data = packets::Packet::Transfer(Transfer {
            server_address: " game.example.net ".into(),
            server_port: wire::U16LE(19133),
            reload_world: true,
            ..Default::default()
        });
        let event = TransferTarget::from_packet_data(&data)
            .expect("well-formed target")
            .expect("transfer packet normalizes");
        assert_eq!(event.host, "game.example.net");
        assert!(event.reload_world);
    }

    #[test]
    fn normalization_ignores_non_transfer_packets() {
        let other = packets::Packet::SetTime(packets::SetTime {
            time: wire::ZigZag32(7),
        });
        assert_eq!(
            TransferTarget::from_packet_data(&other).expect("non-transfer normalizes"),
            None
        );
    }

    #[test]
    fn empty_and_whitespace_only_hosts_are_semantic_rejections() {
        assert_eq!(
            TransferTarget::from_packet_data(&transfer_data("", 19133)),
            Err(TransferRejection::EmptyHost)
        );
        assert_eq!(
            TransferTarget::from_packet_data(&transfer_data("   ", 19133)),
            Err(TransferRejection::EmptyHost)
        );
    }

    #[test]
    fn oversize_hosts_are_semantic_rejections_without_truncation() {
        let bytes = "a".repeat(MAX_TRANSFER_HOST_BYTES + 1);
        match TransferTarget::from_packet_data(&transfer_data(&bytes, 19133)) {
            Err(TransferRejection::HostTooLong { bytes }) => {
                assert_eq!(bytes, MAX_TRANSFER_HOST_BYTES + 1);
            }
            other => panic!("oversize host must be rejected, got {other:?}"),
        }
        let exact = "a".repeat(MAX_TRANSFER_HOST_BYTES);
        assert!(
            TransferTarget::from_packet_data(&transfer_data(&exact, 19133))
                .expect("exact bound is well-formed")
                .is_some()
        );
    }

    #[test]
    fn control_characters_are_semantic_rejections() {
        assert_eq!(
            TransferTarget::from_packet_data(&transfer_data("play.exam\x07ple.net", 19133)),
            Err(TransferRejection::InvalidHostCharacter)
        );
        assert_eq!(
            TransferTarget::from_packet_data(&transfer_data("play exam ple.net", 19133)),
            Err(TransferRejection::InvalidHostCharacter)
        );
    }

    #[test]
    fn zero_port_is_a_semantic_rejection() {
        assert_eq!(
            TransferTarget::from_packet_data(&transfer_data("play.example.net", 0)),
            Err(TransferRejection::ZeroPort)
        );
    }

    #[test]
    fn cross_host_targets_are_not_filtered_by_any_allowlist() {
        // Following unrelated hosts is caller policy, separate from well-formedness.
        let event =
            TransferTarget::from_packet_data(&transfer_data("minigames.other-host.example", 19321))
                .expect("well-formed target")
                .expect("cross-host transfer normalizes");
        assert_eq!(event.host, "minigames.other-host.example");
    }
}
