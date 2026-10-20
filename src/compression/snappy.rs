// Copyright 2024 Karpeles Lab Inc.
// Copyright (c) 2012 The Go Authors. All rights reserved.
// Copyright (c) 2019 Klaus Post. All rights reserved.
// Adapted from minlz's Snappy encoder. See THIRD_PARTY_NOTICES.md for its BSD license.

/// A raw Snappy encoder with retained matching state and iterative copy emission.
#[derive(Default)]
pub(super) struct Encoder {
    table: Vec<u32>,
}

impl Encoder {
    /// Appends one independent Snappy block, using only standard literal and copy tags.
    pub(super) fn compress(&mut self, input: &[u8], out: &mut Vec<u8>) {
        crate::batch::write_length(input.len() as u32, out);
        let start = out.len();
        if input.len() < 32 {
            literal(input, out);
            return;
        }
        let bits = if input.len() < 1024 {
            10
        } else if input.len() < 8192 {
            12
        } else {
            14
        };
        self.table.resize(1 << bits, 0);
        self.table.fill(0);
        let mut position = 1;
        let mut pending = 0;
        let mut matched = false;
        'search: loop {
            let mut skip = 32;
            let mut candidate;
            loop {
                let next = position + (skip >> 5);
                skip += 1;
                if next > input.len() - 8 {
                    break 'search;
                }
                let value = word(input, position);
                let hash = (value.wrapping_mul(0x1e35_a7bd) >> (32 - bits)) as usize;
                candidate = self.table[hash] as usize;
                self.table[hash] = position as u32;
                if candidate < position && value == word(input, candidate) {
                    break;
                }
                position = next;
            }
            while candidate > 0 && position > pending && input[candidate - 1] == input[position - 1]
            {
                candidate -= 1;
                position -= 1;
            }
            literal(&input[pending..position], out);
            let base = position;
            let offset = position - candidate;
            position += 4;
            candidate += 4;
            while position + 32 <= input.len()
                && input[position..position + 32] == input[candidate..candidate + 32]
            {
                position += 32;
                candidate += 32;
            }
            while position + 8 <= input.len() {
                let different = u64::from_le_bytes(
                    input[position..position + 8]
                        .try_into()
                        .expect("bounded match"),
                ) ^ u64::from_le_bytes(
                    input[candidate..candidate + 8]
                        .try_into()
                        .expect("bounded candidate"),
                );
                if different != 0 {
                    let matched = (different.trailing_zeros() / 8) as usize;
                    position += matched;
                    candidate += matched;
                    break;
                }
                position += 8;
                candidate += 8;
            }
            while position < input.len() && input[position] == input[candidate] {
                position += 1;
                candidate += 1;
            }
            copy(offset, position - base, out);
            matched = true;
            pending = position;
            if position >= input.len() - 8 {
                break;
            }
            let hash =
                (word(input, position - 1).wrapping_mul(0x1e35_a7bd) >> (32 - bits)) as usize;
            self.table[hash] = (position - 1) as u32;
        }
        literal(&input[pending..], out);
        if matched && out.len() - start >= input.len() - input.len() / 32 {
            out.truncate(start);
            literal(input, out);
        }
    }
}

/// Loads one bounded match candidate without platform-specific instructions.
#[inline]
fn word(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("bounded match word"),
    )
}

/// Emits one literal, including the extended length form when needed.
fn literal(input: &[u8], out: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    let length = (input.len() - 1) as u32;
    if length < 60 {
        out.push((length as u8) << 2);
    } else {
        let bytes = ((u32::BITS - length.leading_zeros()).div_ceil(8)) as usize;
        out.push(((59 + bytes) as u8) << 2);
        out.extend_from_slice(&length.to_le_bytes()[..bytes]);
    }
    out.extend_from_slice(input);
}

/// Emits bounded copies iteratively, including matches spanning a complete large batch.
fn copy(offset: usize, mut length: usize, out: &mut Vec<u8>) {
    while length != 0 {
        let take = length.min(64);
        if (4..=11).contains(&take) && offset < 2048 {
            out.extend_from_slice(&[
                (((offset >> 8) as u8) << 5) | (((take - 4) as u8) << 2) | 1,
                offset as u8,
            ]);
        } else if offset <= u16::MAX as usize {
            out.extend_from_slice(&[
                (((take - 1) as u8) << 2) | 2,
                offset as u8,
                (offset >> 8) as u8,
            ]);
        } else {
            out.push((((take - 1) as u8) << 2) | 3);
            out.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        length -= take;
    }
}

/// Decodes a complete raw block, retaining literal-only input storage when possible.
pub(super) fn decompress(body: &bytes::Bytes, length: usize) -> Option<bytes::Bytes> {
    let header = body.iter().position(|byte| byte & 0x80 == 0)? + 1;
    let input = &body[header..];
    if let Some((count, prefix)) = read_literal(input)
        && prefix + count == input.len()
        && count == length
    {
        return Some(body.slice(body.len() - length..));
    }
    let mut output = vec![0; length];
    decompress_into(body, &mut output)?;
    Some(output.into())
}

/// Fills declared-size initialized output; only completed bytes contribute to decoded output.
pub(super) fn decompress_into(body: &[u8], output: &mut [u8]) -> Option<()> {
    let header = body.iter().position(|byte| byte & 0x80 == 0)? + 1;
    let mut input = &body[header..];
    let mut position = 0;
    while let Some(&tag) = input.first() {
        if tag & 3 == 0 {
            if tag < 32 && input.len() >= 9 && output.len() - position >= 8 {
                let count = 1 + usize::from(tag >> 2);
                output[position..position + 8].copy_from_slice(&input[1..9]);
                position += count;
                input = &input[1 + count..];
                continue;
            }
            let (count, prefix) = read_literal(input)?;
            if count > output.len() - position {
                return None;
            }
            let literal = &input[prefix..];
            // Spare bytes are initialized and overwritten by later tags before exposure.
            if count <= 8 && literal.len() >= 8 && output.len() - position >= 8 {
                output[position..position + 8].copy_from_slice(&literal[..8]);
            } else {
                output[position..position + count].copy_from_slice(&literal[..count]);
            }
            position += count;
            input = &literal[count..];
            continue;
        }
        if tag & 3 == 1 && input.len() >= 2 && output.len() - position >= 16 {
            let count = 4 + usize::from((tag >> 2) & 7);
            let offset = (usize::from(tag & 0xe0) << 3) | usize::from(input[1]);
            if offset >= count && offset <= position {
                let start = position - offset;
                output.copy_within(start..start + 16, position);
                position += count;
                input = &input[2..];
                continue;
            }
        }
        let (count, offset, prefix) = match tag & 3 {
            1 => (
                4 + usize::from((tag >> 2) & 7),
                (usize::from(tag & 0xe0) << 3) | usize::from(*input.get(1)?),
                2,
            ),
            2 => (
                1 + usize::from(tag >> 2),
                u16::from_le_bytes(input.get(1..3)?.try_into().ok()?) as usize,
                3,
            ),
            _ => (
                1 + usize::from(tag >> 2),
                u32::from_le_bytes(input.get(1..5)?.try_into().ok()?) as usize,
                5,
            ),
        };
        if offset == 0 || offset > position || count > output.len() - position {
            return None;
        }
        let start = position - offset;
        // Fixed-width copies may touch future scratch; their logical bytes use only prior output.
        if count <= 16 && offset >= count && output.len() - position >= 16 {
            output.copy_within(start..start + 16, position);
        } else if offset >= 64 && output.len() - position >= 64 {
            let (completed, remaining) = output.split_at_mut(position);
            remaining[..64].copy_from_slice(&completed[start..start + 64]);
        } else if offset == 1 {
            let byte = output[position - 1];
            output[position..position + count].fill(byte);
        } else {
            let mut copied = 0;
            while copied < count {
                let take = (offset + copied).min(count - copied);
                output.copy_within(start..start + take, position + copied);
                copied += take;
            }
        }
        position += count;
        input = &input[prefix..];
    }
    (position == output.len()).then_some(())
}

/// Reads one standard literal's validated length and prefix width.
#[inline]
fn read_literal(input: &[u8]) -> Option<(usize, usize)> {
    let (&tag, mut data) = input.split_first()?;
    if tag & 3 != 0 {
        return None;
    }
    let code = usize::from(tag >> 2);
    let length = if code < 60 {
        code + 1
    } else {
        let count = code - 59;
        let mut length = [0; 4];
        length[..count].copy_from_slice(data.get(..count)?);
        data = &data[count..];
        (u32::from_le_bytes(length) as usize).checked_add(1)?
    };
    data.get(..length)?;
    Some((length, input.len() - data.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_copies_preserve_short_matches_and_following_literals() {
        for offset in [1, 2, 7, 14, 16, 64, 65] {
            for count in [1, 5, 8, 9, 16, 17, 32, 64] {
                let prefix: Vec<_> = (0..offset).map(|index| index as u8).collect();
                let tail = [0xff; 17];
                let length = offset + count + tail.len();
                let mut wire = Vec::new();
                crate::batch::write_length(length as u32, &mut wire);
                literal(&prefix, &mut wire);
                copy(offset, count, &mut wire);
                literal(&tail, &mut wire);
                let expected = snap::raw::Decoder::new().decompress_vec(&wire).unwrap();
                let mut output = vec![0x5a; length];
                assert_eq!(decompress_into(&wire, &mut output), Some(()));
                assert_eq!(output, expected, "offset {offset}, count {count}");
            }
        }
    }
}
