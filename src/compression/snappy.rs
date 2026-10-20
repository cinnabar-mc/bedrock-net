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
            position += 1;
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

/// Decodes bounded standard Snappy tags into initialized output, without an initial zero fill.
pub(super) fn decompress(body: &bytes::Bytes, length: usize) -> Option<bytes::Bytes> {
    let prefix = body.iter().position(|byte| byte & 0x80 == 0)? + 1;
    let mut input = &body[prefix..];
    if let Some((literal, rest)) = snappy_literal(input)
        && rest.is_empty()
        && literal.len() == length
    {
        return Some(body.slice(body.len() - length..));
    }
    let mut output = Vec::with_capacity(length);
    while let Some(&tag) = input.first() {
        if tag & 3 == 0 {
            let (literal, rest) = snappy_literal(input)?;
            if literal.len() > length - output.len() {
                return None;
            }
            output.extend_from_slice(literal);
            input = rest;
            continue;
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
        if offset == 0 || offset > output.len() || count > length - output.len() {
            return None;
        }
        let start = output.len() - offset;
        let mut available = offset;
        let mut remaining = count;
        while remaining != 0 {
            let take = remaining.min(available);
            output.extend_from_within(start..start + take);
            available += take;
            remaining -= take;
        }
        input = &input[prefix..];
    }
    (output.len() == length).then(|| output.into())
}

/// Reads one complete raw Snappy literal, leaving copy tags to the reference decoder.
#[inline]
fn snappy_literal(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, mut input) = input.split_first()?;
    if tag & 3 != 0 {
        return None;
    }
    let code = usize::from(tag >> 2);
    let length = if code < 60 {
        code + 1
    } else {
        let count = code - 59;
        let mut length = [0; 4];
        length[..count].copy_from_slice(input.get(..count)?);
        input = &input[count..];
        (u32::from_le_bytes(length) as usize).checked_add(1)?
    };
    Some((input.get(..length)?, input.get(length..)?))
}
