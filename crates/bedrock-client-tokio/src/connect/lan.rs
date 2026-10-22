// SPDX-License-Identifier: MIT

//! Directed LAN discovery and association setup on the same original signaling owner.

use crate::transport::Transport;
use nethernet_tokio::{ConnectionConfig, LanConfig, LanSignaling, NetherClient, ServerData};
use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// Exact advertisement matching; account and local-level eligibility are checked by the caller.
#[derive(Clone)]
pub enum LanSelection {
    /// The existing direct offline route requires self-signed admission and current protocol.
    SelfSigned,
    /// The existing direct online route requires online admission and current protocol.
    Online,
    /// A caller-prequalified local level uses its existing finite directed discovery budget.
    Local {
        /// Exact level selected by the original local-world owner.
        level: String,
        /// Original discovery allowance, clipped to the first overall cutoff.
        discovery_budget: Duration,
    },
}

/// Actual caller-owned admission/transport policy; metadata cannot manufacture these capabilities.
#[derive(Clone)]
pub struct DirectedLanConfig {
    /// Original identity, trust, ICE, byte limits and answer-admission policy.
    pub connection: ConnectionConfig,
    /// Exact existing wire advertisement route to match.
    pub selection: LanSelection,
    /// Caller-owned nonce bound for online or selected-local admission.
    pub max_nonce_bytes: usize,
    /// Original credential cutoff; None is the explicit offline path.
    pub credential_expires: Option<Instant>,
}

/// Connects compatible IPv4 answers under one first cutoff and drops all losing actual owners.
/// An explicit nonzero ICE port serializes attempts; ephemeral bindings race independently.
pub async fn connect_resolved(
    addresses: impl Iterator<Item = SocketAddr>,
    options: &DirectedLanConfig,
    deadline: tokio::time::Instant,
) -> io::Result<Transport> {
    let deadline = options
        .credential_expires
        .map_or(deadline, |expires| deadline.min(expires.into()));
    super::check(deadline, options.credential_expires)?;
    let parallel = options
        .connection
        .client_ice
        .as_ref()
        .and_then(|ice| ice.bind_addr)
        .is_none_or(|bind| bind.port() == 0);
    let result = super::resolved(addresses, true, parallel, deadline, |address| async move {
        connect_directed(address, options, deadline)
            .await
            .map(|(transport, _)| transport)
    })
    .await;
    super::check(deadline, options.credential_expires)?;
    result
}

/// Discovers and connects the exact supplied endpoint without changing trust, grants or close policy.
pub async fn connect_directed(
    address: SocketAddr,
    options: &DirectedLanConfig,
    deadline: tokio::time::Instant,
) -> io::Result<(Transport, u64)> {
    if !address.is_ipv4() || address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid directed LAN endpoint",
        ));
    }
    let deadline = options
        .credential_expires
        .map_or(deadline, |expires| deadline.min(expires.into()));
    super::check(deadline, options.credential_expires)?;
    let result = super::before_deadline(deadline, connect_route(address, options, deadline)).await;
    super::check(deadline, options.credential_expires)?;
    result
}

/// Owns original discovery polls and moves that same signaling receiver into its Ready association.
async fn connect_route(
    address: SocketAddr,
    options: &DirectedLanConfig,
    deadline: tokio::time::Instant,
) -> io::Result<(Transport, u64)> {
    let selected = match &options.selection {
        LanSelection::Local {
            level,
            discovery_budget,
        } => Some((level.as_str(), *discovery_budget)),
        _ => None,
    };
    let connection_type = ServerData::new(String::new(), String::new()).connection_type;
    let local = if let Some(bind) = options
        .connection
        .client_ice
        .as_ref()
        .and_then(|ice| ice.bind_addr)
    {
        bind
    } else {
        let route = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        route.connect(address).await?;
        SocketAddr::new(route.local_addr()?.ip(), 0)
    };
    let signaling = LanSignaling::with_config(
        rand::random(),
        SocketAddr::new(local.ip(), 0),
        LanConfig {
            broadcast_address: Some(address),
            ..LanConfig::default()
        },
    )
    .await
    .map_err(io::Error::other)?;
    let discovery_deadline = selected
        .map(|(_, budget)| {
            tokio::time::Instant::now()
                .checked_add(budget)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid local LAN discovery budget",
                    )
                })
        })
        .transpose()?
        .map(|until| deadline.min(until));
    let mut skipped = 0u64;
    let discovering = async {
        let mut polls = tokio::time::interval(std::time::Duration::from_millis(50));
        loop {
            polls.tick().await;
            let mut found = None;
            for (id, data) in signaling.discover().await {
                if signaling.get_address(id).await == Some(address)
                    && selected.is_none_or(|(level, _)| data.level_name == level)
                {
                    if selected.is_some() {
                        if !data.flag_b {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "local LAN peer does not advertise offline admission",
                            ));
                        }
                        if data.connection_type != connection_type
                            || data.session_id.is_empty()
                            || data.session_id.len() > options.max_nonce_bytes
                            || data.session_id.chars().any(char::is_control)
                        {
                            skipped = skipped.saturating_add(1);
                            continue;
                        }
                    }
                    found = Some((id, data));
                    break;
                }
            }
            if let Some(found) = found {
                break Ok(found);
            }
        }
    };
    let discovered = match discovery_deadline {
        Some(until) => {
            super::check(until, options.credential_expires)?;
            let data = tokio::time::timeout_at(until, discovering).await;
            match super::check(until, options.credential_expires) {
                Ok(()) => data.map_err(|_| super::timed_out()).and_then(|data| data),
                Err(error) => Err(error),
            }
        }
        None => discovering.await,
    };
    if skipped != 0 {
        tracing::warn!(
            count = skipped,
            "skipped unsupported selected local LAN metadata"
        );
    }
    let (id, data) = discovered?;
    if matches!(options.selection, LanSelection::Online) {
        if !data.flag_a {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LAN peer does not advertise online admission",
            ));
        }
        if data.session_id.is_empty()
            || data.session_id.len() > options.max_nonce_bytes
            || data.session_id.chars().any(char::is_control)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "LAN peer advertises an invalid admission nonce",
            ));
        }
    } else if !data.flag_b || data.session_id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "LAN peer does not advertise self-signed admission with a nonce",
        ));
    }
    if data.connection_type != connection_type
        || (selected.is_none()
            && data.protocol_version != bedrock_protocol::PROTOCOL_VERSION as u32)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "LAN peer advertises an incompatible transport or protocol",
        ));
    }
    let mut config = options.connection.clone();
    if let Some(ice) = &mut config.client_ice {
        ice.bind_addr = Some(local);
    }
    super::check(deadline, options.credential_expires)?;
    config.timeouts.negotiation = config
        .timeouts
        .negotiation
        .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
    let connection = NetherClient::connect_with(signaling, id.to_string(), config)
        .await
        .map_err(io::Error::other)?;
    super::check(deadline, options.credential_expires)?;
    Ok((Transport::from_lan(connection, data.session_id), id))
}
