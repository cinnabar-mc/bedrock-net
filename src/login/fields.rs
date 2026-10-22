//! Shared Go-compatible recognized Login and `ClientData` field matching.

/// Matches Go's Unicode `SimpleFold` for ASCII field names, including its K/S fold orbits.
/// This is confined to outer Login/client fields; JWT claims and JWS headers never use it.
pub(super) fn matches_field(name: &str, expected: &str) -> bool {
    name.chars()
        .map(|rune| match rune {
            '\u{212a}' => 'K',
            '\u{017f}' => 'S',
            rune => rune.to_ascii_uppercase(),
        })
        .eq(expected.chars().map(|rune| rune.to_ascii_uppercase()))
}
