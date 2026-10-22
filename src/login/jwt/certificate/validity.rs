//! Certificate time syntax only; no clock or validity-period authorization is involved.

use super::der;

/// Reads the two required times, preserving the decoder's ignored validity tail.
pub(super) fn valid(mut data: &[u8]) -> Option<()> {
    for _ in 0..2 {
        let (tag, value) = der::any(&mut data)?;
        time(tag, value)?;
    }
    Some(())
}

/// Checks the exact round-trip grammar of UTC or `GeneralizedTime` without constructing an instant.
fn time(tag: u8, value: &[u8]) -> Option<()> {
    let year_width = match tag {
        23 => 2,
        24 => 4,
        _ => return None,
    };
    let (digits, zone) = if value.last() == Some(&b'Z') {
        (&value[..value.len() - 1], &value[value.len() - 1..])
    } else {
        let split = value.len().checked_sub(5)?;
        (&value[..split], &value[split..])
    };
    let fields = digits.len().checked_sub(year_width)?;
    if !(fields == 10 || (tag == 23 && fields == 8)) || !digits.is_ascii() {
        return None;
    }
    let mut year = number(&digits[..year_width])?;
    if tag == 23 {
        year += if year >= 69 { 1900 } else { 2000 };
    }
    let month = number(&digits[year_width..year_width + 2])?;
    let day = number(&digits[year_width + 2..year_width + 4])?;
    let hour = number(&digits[year_width + 4..year_width + 6])?;
    let minute = number(&digits[year_width + 6..year_width + 8])?;
    let second = if fields == 10 {
        number(&digits[year_width + 8..])?
    } else {
        0
    };
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            28 + u16::from(
                year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)),
            )
        }
        _ => return None,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if zone != b"Z" {
        if !matches!(zone[0], b'+' | b'-') {
            return None;
        }
        let hour = number(&zone[1..3])?;
        let minute = number(&zone[3..5])?;
        // Numeric zero formats as Z; minute 60 normalizes, so neither spelling round-trips.
        if hour > 24 || minute > 59 || (hour == 0 && minute == 0) {
            return None;
        }
    }
    Some(())
}

/// Reads the already bounded decimal fields in a certificate time spelling.
fn number(digits: &[u8]) -> Option<u16> {
    digits.iter().try_fold(0, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u16::from(byte - b'0'))
    })
}
