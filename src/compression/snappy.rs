// Copyright 2024 Karpeles Lab Inc.
// Copyright (c) 2012 The Go Authors. All rights reserved.
// Copyright (c) 2019 Klaus Post. All rights reserved.
// Copyright 2016 The Snappy-Go Authors. All rights reserved.
// Rust implementation adapted from HashimTheArab's bedrock-net Snappy implementation.
// Adapted from minlz and S2's Snappy encoders. See THIRD_PARTY_NOTICES.md for its BSD license.

use std::borrow::Cow;

/// A raw Snappy encoder with matching scratch and iterative copy emission.
#[derive(Default)]
pub(super) struct Encoder {
    table: Vec<u32>,
    small_output: Vec<u8>,
}

impl Encoder {
    /// Returns one independent Snappy block, borrowing bounded scratch for small inputs.
    pub(super) fn compress(&mut self, input: &[u8]) -> Cow<'_, [u8]> {
        if input.len() <= 65536 {
            let maximum = input.len() * 2 + 32;
            if self.small_output.len() < maximum {
                self.small_output
                    .reserve_exact(maximum - self.small_output.len());
                self.small_output.resize(maximum, 0);
            }
            let mut encoded = SliceOutput {
                bytes: &mut self.small_output,
                length: 0,
            };
            match input.len() {
                0..=1023 => encode_small::<1024>(input, &mut self.table, &mut encoded),
                1024..=4095 => encode_small::<4096>(input, &mut self.table, &mut encoded),
                4096..=16383 => encode_sparse::<4096, true>(input, &mut self.table, &mut encoded),
                _ => encode_sparse::<16384, false>(input, &mut self.table, &mut encoded),
            }
            Cow::Borrowed(&encoded.bytes[..encoded.length])
        } else {
            let mut out = Vec::with_capacity(snap::raw::max_compress_len(input.len()));
            encode_sparse::<16384, false>(input, &mut self.table, &mut out);
            Cow::Owned(out)
        }
    }
}

/// Uses a dense four-byte search with a fixed table size for each small input range.
fn encode_small<const TABLE_SIZE: usize>(
    input: &[u8],
    table: &mut Vec<u32>,
    out: &mut impl Output,
) {
    let mut length = input.len() as u32;
    while length >= 128 {
        out.push(length as u8 | 128);
        length >>= 7;
    }
    out.push(length as u8);
    let start = out.len();
    if input.len() < 32 {
        literal(input, input.len(), out);
        return;
    }
    let bits = TABLE_SIZE.ilog2();
    table.resize(TABLE_SIZE, 0);
    let table: &mut [u32; TABLE_SIZE] = table
        .as_mut_slice()
        .try_into()
        .expect("matching table size");
    table.fill(0);
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
            candidate = table[hash] as usize;
            table[hash] = position as u32;
            if candidate < position && value == word(input, candidate) {
                break;
            }
            position = next;
        }
        while candidate > 0 && position > pending && input[candidate - 1] == input[position - 1] {
            candidate -= 1;
            position -= 1;
        }
        literal(&input[pending..], position - pending, out);
        let base = position;
        let offset = position - candidate;
        position += 4;
        candidate += 4;
        position += common_prefix(&input[position..], &input[candidate..]);
        copy(offset, position - base, out);
        matched = true;
        pending = position;
        if position >= input.len() - 8 {
            break;
        }
        let hash = (word(input, position - 1).wrapping_mul(0x1e35_a7bd) >> (32 - bits)) as usize;
        table[hash] = (position - 1) as u32;
    }
    literal(&input[pending..], input.len() - pending, out);
    if matched && out.len() - start >= input.len() - input.len() / 32 {
        out.truncate(start);
        literal(input, input.len(), out);
    }
}

/// Encodes a complete input with five-byte short probes or six-byte large probes.
fn encode_sparse<const TABLE_SIZE: usize, const SHORT: bool>(
    input: &[u8],
    table: &mut Vec<u32>,
    out: &mut impl Output,
) {
    debug_assert!(if SHORT {
        (4096..16384).contains(&input.len()) && TABLE_SIZE == 4096
    } else {
        input.len() >= 16384 && TABLE_SIZE == 16384
    });
    let mut length = input.len() as u32;
    while length >= 128 {
        out.push(length as u8 | 128);
        length >>= 7;
    }
    out.push(length as u8);
    let start = out.len();
    let bits = TABLE_SIZE.ilog2();
    table.resize(TABLE_SIZE, 0);
    let table: &mut [u32; TABLE_SIZE] = table
        .as_mut_slice()
        .try_into()
        .expect("matching table size");
    table.fill(0);
    let margin = if SHORT { 8 } else { 16 };
    let mut position = 1;
    let mut pending = 0;
    let mut repeat = 1;
    let mut matched = false;
    'search: while position + margin <= input.len() {
        let mut candidate;
        let mut repeated = false;
        loop {
            if !SHORT && position + 16 > input.len() {
                break 'search;
            }
            let next = if SHORT {
                let next = position + 4 + ((position - pending) >> 5);
                if next >= input.len() - 8 {
                    break 'search;
                }
                next
            } else {
                0
            };
            let value = wide_word(input, position);
            let index = hash::<SHORT>(value, bits);
            candidate = table[index] as usize;
            let second_index = if SHORT {
                hash::<SHORT>(value >> 8, bits)
            } else {
                0
            };
            let second_candidate = if SHORT {
                table[second_index] as usize
            } else {
                0
            };
            let third_index = if SHORT {
                hash::<SHORT>(value >> 16, bits)
            } else {
                0
            };
            // Both candidates must be read before either colliding entry is replaced.
            table[index] = position as u32;
            if SHORT {
                table[second_index] = (position + 1) as u32;
            }
            debug_assert!(repeat > 0 && repeat <= position);
            if (value >> 8) as u32 == word(input, position - repeat + 1) {
                position += 1;
                candidate = position - repeat;
                repeated = true;
                break;
            }
            if value as u32 == word(input, candidate) {
                break;
            }
            if SHORT {
                // Read after the first two writes, but only when the first candidate failed.
                candidate = table[third_index] as usize;
                debug_assert!(second_candidate < position + 1);
                if (value >> 8) as u32 == word(input, second_candidate) {
                    table[third_index] = (position + 2) as u32;
                    candidate = second_candidate;
                    position += 1;
                    break;
                }
                table[third_index] = (position + 2) as u32;
                debug_assert!(candidate < position + 2);
                if (value >> 16) as u32 == word(input, candidate) {
                    position += 2;
                    break;
                }
            }
            position = if SHORT {
                next
            } else {
                position + 4 + ((position - pending) >> 6)
            };
        }
        debug_assert!(candidate < position);
        while candidate > 0 && position > pending && input[candidate - 1] == input[position - 1] {
            candidate -= 1;
            position -= 1;
        }
        literal(&input[pending..], position - pending, out);
        loop {
            debug_assert!(candidate < position);
            let base = position;
            repeat = position - candidate;
            position += 4;
            candidate += 4;
            while !SHORT
                && position + 32 <= input.len()
                && input[position..position + 32] == input[candidate..candidate + 32]
            {
                position += 32;
                candidate += 32;
            }
            position += common_prefix(&input[position..], &input[candidate..]);
            copy(repeat, position - base, out);
            matched = true;
            pending = position;
            let at_end = if SHORT {
                position >= input.len() - 8
            } else {
                position + 16 > input.len()
            };
            if at_end {
                break 'search;
            }
            // Extra immediate-match table updates after repeats lose later matches.
            if repeated {
                continue 'search;
            }
            let value = wide_word(input, position - 2);
            let previous = hash::<SHORT>(value, bits);
            let current = hash::<SHORT>(value >> 16, bits);
            // Look up before either write, including when both hashes select one entry.
            candidate = table[current] as usize;
            table[previous] = (position - 2) as u32;
            table[current] = position as u32;
            debug_assert!(candidate < position);
            if (value >> 16) as u32 != word(input, candidate) {
                position += 1;
                break;
            }
        }
    }
    literal(&input[pending..], input.len() - pending, out);
    if matched && out.len() - start >= input.len() - input.len() / 32 {
        out.truncate(start);
        literal(input, input.len(), out);
    }
}

/// The writes needed to emit raw Snappy tags and literals.
trait Output {
    /// Returns the logical byte count.
    fn len(&self) -> usize;
    /// Appends one tag or length byte.
    fn push(&mut self, byte: u8);
    /// Appends a fixed tag or literal.
    fn extend_from_slice(&mut self, bytes: &[u8]);
    /// Discards an ineffective encoding before emitting a literal block.
    fn truncate(&mut self, length: usize);
    /// Copies literal bytes, allowing bounded writes beyond the logical cursor.
    fn literal(&mut self, input: &[u8], count: usize);
}
impl Output for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }
    fn truncate(&mut self, length: usize) {
        Vec::truncate(self, length);
    }
    #[inline(always)]
    fn literal(&mut self, input: &[u8], count: usize) {
        let out = self;
        let width = if count <= 8 {
            8
        } else if count <= 16 {
            16
        } else if count <= 32 {
            32
        } else {
            0
        };
        if width != 0 && input.len() >= width && out.capacity() - out.len() >= width {
            let start = out.len();
            out.resize(start + width, 0);
            match width {
                8 => out[start..start + 8].copy_from_slice(&input[..8]),
                16 => out[start..start + 16].copy_from_slice(&input[..16]),
                32 => out[start..start + 32].copy_from_slice(&input[..32]),
                _ => unreachable!(),
            }
            out.truncate(start + count);
        } else {
            out.extend_from_slice(&input[..count]);
        }
    }
}
/// Tracks emitted bytes within retained initialized small-batch storage.
struct SliceOutput<'a> {
    bytes: &'a mut [u8],
    length: usize,
}
impl Output for SliceOutput<'_> {
    fn len(&self) -> usize {
        self.length
    }
    fn push(&mut self, byte: u8) {
        self.bytes[self.length] = byte;
        self.length += 1;
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes[self.length..][..bytes.len()].copy_from_slice(bytes);
        self.length += bytes.len();
    }
    fn truncate(&mut self, length: usize) {
        self.length = length;
    }
    #[inline(always)]
    fn literal(&mut self, input: &[u8], count: usize) {
        let width = if count <= 8 {
            8
        } else if count <= 16 {
            16
        } else if count <= 32 {
            32
        } else {
            0
        };
        if width != 0 && input.len() >= width && self.bytes.len() - self.length >= width {
            let output = &mut self.bytes[self.length..];
            match width {
                8 => output[..8].copy_from_slice(&input[..8]),
                16 => output[..16].copy_from_slice(&input[..16]),
                32 => output[..32].copy_from_slice(&input[..32]),
                _ => unreachable!(),
            }
            self.length += count;
        } else {
            self.extend_from_slice(&input[..count]);
        }
    }
}

/// Counts matching bytes without repeated bounds checks for each indexed word.
#[inline(always)]
fn common_prefix(left: &[u8], right: &[u8]) -> usize {
    let mut matched = 0;
    for (left, right) in left.as_chunks::<8>().0.iter().zip(right.as_chunks::<8>().0) {
        let different = u64::from_le_bytes(*left) ^ u64::from_le_bytes(*right);
        if different != 0 {
            return matched + (different.trailing_zeros() / 8) as usize;
        }
        matched += 8;
    }
    matched
        + left[matched..]
            .iter()
            .zip(&right[matched..])
            .take_while(|(left, right)| left == right)
            .count()
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

/// Loads eight bytes for hash and repeat probes.
#[inline]
fn wide_word(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("bounded match word"),
    )
}

/// Hashes five or six input bytes into the selected matching table.
#[inline]
fn hash<const SHORT: bool>(value: u64, bits: u32) -> usize {
    if SHORT {
        ((value << 24).wrapping_mul(0x00cf_1bbc_dcbb) >> (64 - bits)) as usize
    } else {
        ((value << 16).wrapping_mul(227_718_039_650_203) >> (64 - bits)) as usize
    }
}

/// Emits a literal with fixed-width copies only within valid input and initialized output.
#[inline(always)]
fn literal(input: &[u8], count: usize, out: &mut impl Output) {
    if count == 0 {
        return;
    }
    let length = (count - 1) as u32;
    if length < 60 {
        out.push((length as u8) << 2);
    } else {
        let bytes = ((u32::BITS - length.leading_zeros()).div_ceil(8)) as usize;
        out.push(((59 + bytes) as u8) << 2);
        out.extend_from_slice(&length.to_le_bytes()[..bytes]);
    }
    out.literal(input, count);
}

/// Emits bounded copies iteratively, then writes the final short tag once.
#[inline(always)]
fn copy(offset: usize, mut length: usize, out: &mut impl Output) {
    while length > 64 {
        let take = if length < 68 { 60 } else { 64 };
        copy_tag(offset, take, out);
        length -= take;
    }
    if length != 0 {
        copy_tag(offset, length, out);
    }
}

/// Emits one standard copy tag for one through sixty-four bytes.
#[inline(always)]
fn copy_tag(offset: usize, length: usize, out: &mut impl Output) {
    debug_assert!((1..=64).contains(&length));
    if (4..=11).contains(&length) && offset < 2048 {
        out.extend_from_slice(&[
            (((offset >> 8) as u8) << 5) | (((length - 4) as u8) << 2) | 1,
            offset as u8,
        ]);
    } else if offset <= u16::MAX as usize {
        out.extend_from_slice(&[
            (((length - 1) as u8) << 2) | 2,
            offset as u8,
            (offset >> 8) as u8,
        ]);
    } else {
        out.push((((length - 1) as u8) << 2) | 3);
        out.extend_from_slice(&(offset as u32).to_le_bytes());
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
    fn prefix_matching_stops_at_word_and_slice_boundaries() {
        for length in 0..=130 {
            let left: Vec<_> = (0..length).map(|index| index as u8).collect();
            for matched in 0..=length {
                let mut right = left.clone();
                right.extend_from_slice(&[0xff; 9]);
                if matched < length {
                    right[matched] ^= 0xff;
                }
                assert_eq!(common_prefix(&left, &right), matched);
                assert_eq!(common_prefix(&right, &left), matched);
            }
        }
    }

    #[test]
    fn literal_copies_keep_logical_lengths_and_input_boundaries() {
        let source: Vec<_> = (0..100).map(|index| index as u8).collect();
        for count in 0..=65 {
            for extra in 0..=32 {
                for capacity in [0, 256] {
                    let mut wire = vec![0x5a; capacity];
                    wire.clear();
                    crate::batch::write_length((count + 3) as u32, &mut wire);
                    literal(&source[..count + extra], count, &mut wire);
                    literal(&[0xff; 3], 3, &mut wire);
                    let mut expected = source[..count].to_vec();
                    expected.extend_from_slice(&[0xff; 3]);
                    assert_eq!(
                        snap::raw::Decoder::new().decompress_vec(&wire).unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn retained_output_storage_is_bounded_across_input_sizes() {
        let mut encoder = Encoder::default();
        for length in [8191, 8192, 8193, 16383, 16384, 65535, 65536, 65537, 1] {
            let input: Vec<_> = (0..length).map(|index| (index % 251) as u8).collect();
            let wire = encoder.compress(&input);
            assert_eq!(
                snap::raw::Decoder::new().decompress_vec(&wire).unwrap(),
                input
            );
            assert!(encoder.small_output.len() <= 2 * 65536 + 32);
            assert!(encoder.small_output.capacity() <= 2 * 65536 + 32);
        }
    }

    #[test]
    fn slice_literals_preserve_logical_lengths_and_input_boundaries() {
        let source: Vec<_> = (0..97).map(|index| index as u8).collect();
        for count in 0..=65 {
            for extra in 0..=32 {
                let mut storage = [0x5a; 160];
                let mut wire = SliceOutput {
                    bytes: &mut storage,
                    length: 0,
                };
                wire.push((count + 3) as u8);
                literal(&source[..count + extra], count, &mut wire);
                literal(&[0xff; 3], 3, &mut wire);
                let mut expected = source[..count].to_vec();
                expected.extend_from_slice(&[0xff; 3]);
                assert_eq!(
                    snap::raw::Decoder::new()
                        .decompress_vec(&wire.bytes[..wire.length])
                        .unwrap(),
                    expected
                );
            }
        }
    }

    #[test]
    fn fixed_width_copies_preserve_short_matches_and_following_literals() {
        for offset in [1, 2, 7, 14, 16, 64, 65] {
            for count in [1, 5, 8, 9, 16, 17, 32, 64, 65, 66, 67, 68, 127, 128, 129] {
                let prefix: Vec<_> = (0..offset).map(|index| index as u8).collect();
                let tail = [0xff; 17];
                let length = offset + count + tail.len();
                let mut wire = Vec::new();
                crate::batch::write_length(length as u32, &mut wire);
                literal(&prefix, prefix.len(), &mut wire);
                copy(offset, count, &mut wire);
                literal(&tail, tail.len(), &mut wire);
                let expected = snap::raw::Decoder::new().decompress_vec(&wire).unwrap();
                let mut output = vec![0x5a; length];
                assert_eq!(decompress_into(&wire, &mut output), Some(()));
                assert_eq!(output, expected, "offset {offset}, count {count}");
            }
        }
    }
}
