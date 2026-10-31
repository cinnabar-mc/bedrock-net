//! Caller-owned device overlays retain unrelated Login claims and the original document.
#![cfg(feature = "login")]

use bedrock_net::login::client_data::{DeviceProfile, RawClientData, default_input_mode};
use serde_json::{json, value::RawValue};

#[test]
fn profile_overlay_preserves_empty_hash_unknown_claims_and_original_clone() {
    let input = r#"{"CurrentInputMode":1,"DeviceId":"previous-id","DeviceModel":"Previous hardware","GameVersion":"1.26.60","SkinId":"kept","ProfileHash":"","Opaque":{"n":1e400}}"#;
    let original = RawClientData::from_raw(&RawValue::from_string(input.into()).unwrap()).unwrap();
    let profile: DeviceProfile = serde_json::from_value(json!({
        "os":1, "model":"Caller hardware", "id":"00112233445566778899aabbccddeeff"
    }))
    .unwrap();
    for _ in 0..2 {
        let mut modified = original.clone();
        profile.apply(&mut modified).unwrap();
        assert_eq!(
            modified.read::<String>("DeviceId").unwrap().as_deref(),
            Some(profile.id.as_str())
        );
        assert_eq!(
            modified.read::<String>("DeviceModel").unwrap().as_deref(),
            Some(profile.model.as_str())
        );
        assert_eq!(modified.integer("DefaultInputMode").unwrap(), Some(2));
        assert_eq!(modified.integer("CurrentInputMode").unwrap(), Some(1));
        assert_eq!(modified.integer("PlatformType").unwrap(), Some(1));
        assert_eq!(
            modified.read::<String>("ProfileHash").unwrap().as_deref(),
            Some("")
        );
        assert_eq!(
            modified.read::<String>("SkinId").unwrap().as_deref(),
            Some("kept")
        );
        let encoded = serde_json::to_string(&modified).unwrap();
        assert!(encoded.contains(r#""Opaque":{"n":1e400}"#));
        let ordered = [
            "CurrentInputMode",
            "DefaultInputMode",
            "DeviceId",
            "DeviceModel",
            "DeviceOS",
            "GameVersion",
        ];
        assert!(
            ordered
                .windows(2)
                .all(|pair| encoded.find(pair[0]) < encoded.find(pair[1]))
        );
        assert_eq!(serde_json::to_string(&original).unwrap(), input);
    }
    assert_eq!(
        serde_json::to_value(&profile).unwrap(),
        json!({"os":1,"model":"Caller hardware","id":"00112233445566778899aabbccddeeff"})
    );
}

#[test]
fn android_profile_defaults_zero_platform_and_keeps_nonzero_platform() {
    for (os, platform, expected) in [
        (1, None, Some(1)),
        (1, Some(0), Some(1)),
        (1, Some(7), Some(7)),
        (1, Some(-1), Some(-1)),
        (7, None, None),
        (2, Some(0), Some(0)),
    ] {
        let mut value = json!({"CurrentInputMode":3,"SkinData":"kept"});
        if let Some(platform) = platform {
            value["PlatformType"] = json!(platform);
        }
        let mut data = RawClientData::from_value(&value).unwrap();
        DeviceProfile {
            os,
            model: "Caller hardware".into(),
            id: "stable-device".into(),
        }
        .apply(&mut data)
        .unwrap();
        assert_eq!(data.integer("PlatformType").unwrap(), expected);
        assert_eq!(data.integer("DeviceOS").unwrap(), Some(os));
        assert_eq!(data.integer("CurrentInputMode").unwrap(), Some(3));
        assert_eq!(
            data.read::<String>("SkinData").unwrap().as_deref(),
            Some("kept")
        );
    }
    for (os, expected) in [
        (-1, 2),
        (0, 2),
        (1, 2),
        (3, 1),
        (7, 1),
        (8, 1),
        (10, 1),
        (11, 3),
        (12, 3),
        (13, 3),
        (15, 1),
        (999, 2),
    ] {
        assert_eq!(default_input_mode(os), expected, "OS {os}");
    }
}
