use super::*;
use crate::login::jwt;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p384::{ecdsa::SigningKey, pkcs8::EncodePublicKey};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::Write,
    process::{Command, Stdio},
};

/// Uses the same Rust-authored claims in the actual pinned Go projection, without a copied table.
#[test]
fn player_identity_matches_the_original_go_login_projection() {
    let Some(binary) = std::env::var_os("BEDROCK_NET_LOGIN_ORACLE") else {
        assert!(
            std::env::var_os("BEDROCK_NET_REQUIRE_FIXTURES").is_none(),
            "missing fixture: BEDROCK_NET_LOGIN_ORACLE; build tools/go-oracle/cmd/login-check"
        );
        eprintln!(
            "missing-fixture: BEDROCK_NET_LOGIN_ORACLE (build tools/go-oracle/cmd/login-check)"
        );
        return;
    };
    #[derive(Deserialize)]
    struct Projection {
        xuid: String,
        name: String,
        uuid: String,
        playfab_id: String,
        playfab_title_id: String,
    }
    let key = SigningKey::from_slice(&[3; 48]).unwrap();
    let public = STANDARD.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
    for (index, (xuid, legacy)) in [
        ("123", None),
        ("456", Some("")),
        ("00123", None),
        ("123", Some("00000000-0000-4000-8000-000000000011")),
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("Player {index}");
        let playfab_id = format!("original-master-{index}");
        let title_id = format!("original-title-{index}");
        let identity = PlayerIdentity::new(
            xuid,
            name.clone(),
            legacy,
            playfab_id.clone(),
            title_id.clone(),
        )
        .unwrap();
        let claims = jwt::json_line(
            &json!({"xid":xuid,"xname":name,"leguuid":legacy,
                "mid":playfab_id,"tid":title_id,
                "exp":4_070_908_800_u64,"cpk":public}),
            64 * 1024,
        )
        .unwrap();
        let token = jwt::sign(&key, &public, &claims, 64 * 1024).unwrap();
        let mut child = Command::new(&binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the existing Login oracle");
        let input = serde_json::to_vec(&json!({"identity_token":token})).unwrap();
        let written = child.stdin.take().unwrap().write_all(&input);
        let output = child.wait_with_output().expect("reap the Login oracle");
        written.expect("write the identity fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let original: Projection = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(original.xuid, xuid);
        assert_eq!(original.uuid, identity.uuid().to_string());
        assert_eq!(original.name, identity.display_name());
        assert_eq!(original.playfab_id, identity.playfab_id());
        assert_eq!(original.playfab_title_id, identity.playfab_title_id());
    }
}

/// A malformed provider projection cannot become a valid world identity by defaulting fields.
#[test]
fn player_identity_rejects_missing_name_and_invalid_legacy_uuid() {
    for (name, legacy) in [
        ("", None),
        ("Verified", Some("not-a-uuid")),
        ("Verified", Some("00000000-0000-0000-0000-000000000000")),
    ] {
        assert!(matches!(
            PlayerIdentity::new("123", name.into(), legacy, String::new(), String::new()),
            Err(LoginError::Authentication)
        ));
    }
}
