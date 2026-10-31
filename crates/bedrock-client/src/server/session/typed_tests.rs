//! A distinct internal capability exercises type retention without manufacturing provider identity.

use super::super::{Phase, ServerSessionError, ServerSessionEvent, spawn};
use super::*;
use bedrock_net::login::LoginError;
use bedrock_protocol::wire;
use std::{cell::Cell, time::Duration};

struct Marker(Box<u32>);
struct Policy(Cell<usize>);
impl crate::server::policy::sealed::Sealed<Marker> for Policy {}
impl LoginPolicy<Marker> for Policy {
    fn revalidate(&self, login: &Marker, _: SystemTime) -> Result<(), LoginError> {
        assert_eq!(*login.0, 73);
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

/// Holds a distinct capability at the actual post-pack boundary for generic continuation checks.
fn ready(now: Instant) -> ServerWorldReady<Box<u32>, Marker> {
    ServerWorldReady {
        engine: Box::new(SessionEngine {
            login: Marker(Box::new(73)),
            grant: Box::new(91),
            packs: None,
            metadata_limit: 1024 * 1024,
            world: None,
            deadline: now + Duration::from_secs(10),
            phase: Phase::World,
            cache_enabled: false,
        }),
    }
}

/// Supplies generated synthetic world data independently from the Login capability.
fn world() -> ServerWorld {
    ServerWorld {
        start_game: Box::new(packets::StartGame {
            runtime_id: bedrock_protocol::types::ActorRuntimeID(73),
            ..Default::default()
        }),
        items: packets::ItemRegistry::default(),
        creative: packets::CreativeContent::default(),
        max_chunk_radius: 8,
        initial_chunk_radius: None,
    }
}

#[test]
fn distinct_capability_survives_spawn_and_final_handoff_without_projection() {
    let now = Instant::now();
    let utc = SystemTime::UNIX_EPOCH;
    let policy = Policy(Cell::new(0));
    let ready = ready(now);
    let original = ready.login().0.as_ref() as *const u32;
    let grant = ready.grant().as_ref() as *const u32;
    let deadline = ready.deadline();
    let (spawning, _) = ready.start_world(world(), &policy, now, utc).unwrap();
    let ServerSpawnEvent::Send { session, .. } = spawning
        .receive(
            packets::RequestChunkRadius {
                chunk_radius: wire::ZigZag32(5),
                max_chunk_radius: wire::U8(8),
            }
            .into(),
            now,
        )
        .unwrap()
    else {
        panic!("radius did not preserve its continuation")
    };
    let ServerSpawnEvent::Initialized(initialized) = session
        .receive(
            packets::SetLocalPlayerAsInitialized {
                player_id: bedrock_protocol::types::ActorRuntimeID(73),
            }
            .into(),
            now,
        )
        .unwrap()
    else {
        panic!("matching runtime ID did not initialize")
    };
    assert_eq!(initialized.deadline(), deadline);
    let accepted = initialized.finish(&policy, now, utc).unwrap();
    let (login, retained_grant, cache, radius) = accepted.into_parts();
    assert_eq!(login.0.as_ref() as *const u32, original);
    assert_eq!(retained_grant.as_ref() as *const u32, grant);
    assert!(!cache);
    assert_eq!(radius, 5);
    assert_eq!(policy.0.get(), 2);
}

#[test]
fn distinct_capability_keeps_terminal_deadline_before_policy_revalidation() {
    let now = Instant::now();
    let policy = Policy(Cell::new(0));
    let ready = ready(now);
    let deadline = ready.deadline();
    let Err(error) = ready.start_world(world(), &policy, deadline, SystemTime::UNIX_EPOCH) else {
        panic!("expired typed owner started a world")
    };
    let (ready, cause) = error.into_parts();
    assert!(matches!(cause, ServerSessionError::TimedOut));
    assert_eq!(policy.0.get(), 0);
    assert!(
        ready
            .start_world(world(), &policy, now, SystemTime::UNIX_EPOCH)
            .is_err()
    );
}

/// Radius renegotiation updates the policy result without repeating one-time startup effects.
#[test]
fn startup_radius_updates_keep_one_spawn_and_the_final_bounded_radius() {
    for fixed in [None, Some(3)] {
        let mut world = world();
        world.initial_chunk_radius = fixed;
        let (mut startup, _) = spawn::Startup::new(world, 1024 * 1024).unwrap();
        for (index, requested) in [5, 12, 6].into_iter().enumerate() {
            let ServerSessionEvent::Send(packets) = startup
                .receive(
                    packets::RequestChunkRadius {
                        chunk_radius: wire::ZigZag32(requested),
                        max_chunk_radius: wire::U8(16),
                    }
                    .into(),
                )
                .unwrap()
            else {
                panic!("radius update must respond");
            };
            assert_eq!(packets.len(), if index == 0 { 3 } else { 1 });
            assert!(
                matches!(&packets[0], packets::Packet::ChunkRadiusUpdated(radius)
                if radius.chunk_radius.0 == fixed.unwrap_or(requested.min(8)))
            );
            if index == 0 {
                assert!(matches!(&packets[1], packets::Packet::PlayStatus(status)
                    if status.status == bedrock_protocol::enums::PlayStatusType::PlayerSpawn));
                assert!(matches!(&packets[2], packets::Packet::CreativeContent(_)));
            }
        }
        assert!(matches!(
            startup
                .receive(
                    packets::SetLocalPlayerAsInitialized {
                        player_id: bedrock_protocol::types::ActorRuntimeID(73),
                    }
                    .into()
                )
                .unwrap(),
            ServerSessionEvent::Ready
        ));
        assert_eq!(startup.radius(), fixed.unwrap_or(6));
    }
}
