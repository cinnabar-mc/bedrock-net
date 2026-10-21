// Synthetic NumericDate controls for the pinned Go Login and claim owners.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

type offlineTimeFixture struct {
	Name        string `json:"name"`
	Request     []byte `json:"request"`
	Accepted    bool   `json:"accepted"`
	Now         int64  `json:"now"`
	Nanos       int    `json:"nanos"`
	ParseAnchor bool   `json:"parse_anchor"`
}

// offlineTimeFixtures compares exact caller UTC and independently anchors large dates with Parse.
func offlineTimeFixtures() ([]offlineTimeFixture, error) {
	key := offlineKey(7)
	public := login.MarshalPublicKey(&key.PublicKey)
	metadata := map[string]any{"DeviceOS": 1, "GameVersion": "1.26.51", "LanguageCode": "en_US", "SkinId": "synthetic", "ThirdPartyName": "MetadataName", "ServerAddress": "127.0.0.1:19132"}
	client := offlineToken(key, "ES384", public, metadata)
	identity := map[string]any{"extraData": map[string]any{"displayName": "TokenName", "XUID": ""}}
	var fixtures []offlineTimeFixture
	add := func(name, field, value, position string, nanos int, anchor bool) error {
		var claims jwt.Claims
		if err := json.Unmarshal(offlineEncode(map[string]any{field: json.RawMessage(value)}), &claims); err != nil {
			return err
		}
		now := time.Unix(1800000000, int64(nanos))
		accepted := claims.ValidateWithLeeway(jwt.Expected{Time: now}, time.Minute) == nil
		first := map[string]any{"identityPublicKey": public}
		middle := map[string]any{"iss": "Mojang"}
		last := offlineChanged(identity, "iss", "Mojang")
		var chain []string
		if position == "one" {
			chain = []string{offlineToken(key, "ES384", public, offlineChanged(identity, field, json.RawMessage(value)))}
		} else {
			switch position {
			case "inherit":
				first[field] = json.RawMessage(value)
			case "middle":
				middle[field] = json.RawMessage(value)
			case "last":
				last[field] = json.RawMessage(value)
			default:
				return fmt.Errorf("unknown fixture position %s", position)
			}
			chain = []string{offlineToken(key, "ES384", public, first), offlineToken(key, "ES384", public, middle), offlineToken(key, "ES384", public, last)}
		}
		request := offlineFrame(map[string]any{"chain": chain}, client)
		if anchor {
			_, _, auth, err := login.Parse(request, nil)
			if (err == nil) != accepted {
				return fmt.Errorf("time Parse anchor %s changed: %v", name, err)
			}
			if err == nil && auth.XBOXLiveAuthenticated {
				return fmt.Errorf("time fixture authenticated")
			}
		}
		fixtures = append(fixtures, offlineTimeFixture{name, request, accepted, 1800000000, nanos, anchor})
		return nil
	}
	const before int64 = ((1<<63 - 1) - 62135596800) / 1024 * 1024
	values := []struct{ name, value string }{
		{"before_wrap", fmt.Sprint(before)}, {"after_wrap", fmt.Sprint(before + 1024)},
		{"near_max", "9223372036854774784"}, {"minimum", "-9223372036854775808"},
		{"zero", "0"}, {"null", "null"},
	}
	for _, field := range []string{"exp", "nbf", "iat"} {
		for _, v := range values {
			for _, position := range []string{"one", "inherit", "middle", "last"} {
				if err := add(field+"_"+v.name+"_"+position, field, v.value, position, 0, true); err != nil {
					return nil, err
				}
			}
		}
		for _, delta := range []int64{-61, -60, -59, 0, 59, 60, 61} {
			for _, nanos := range []int{0, 500000000} {
				name := fmt.Sprintf("%s_leeway_%d_%d", field, delta, nanos)
				if err := add(name, field, fmt.Sprint(1800000000+delta), "one", nanos, false); err != nil {
					return nil, err
				}
			}
		}
		if err := add(field+"_fraction", field, "1800000060.99", "one", 0, false); err != nil {
			return nil, err
		}
	}
	return fixtures, nil
}
