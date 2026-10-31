// EOF behavior adapted from klauspost/compress/flate (BSD-3-Clause); see NOTICE.
// Copyright (c) 2012 The Go Authors. All rights reserved.
// Copyright (c) 2019 Klaus Post. All rights reserved.

//! Identifies an unfinished reference whose decoded prefix remains available to packet validation.

/// Recognizes reference reads that can end at the physical input boundary.
/// Other incomplete blocks still require a complete compressed stream.
pub(super) fn releases_prefix(body: &[u8]) -> bool {
    reference_tail(&mut Bits { body, position: 0 }).unwrap_or(false)
}

struct Bits<'a> {
    body: &'a [u8],
    position: usize,
}

impl Bits<'_> {
    /// Returns the number of original input bits that have not been consumed.
    fn remaining(&self) -> usize {
        self.body.len() * 8 - self.position
    }

    /// Reads little-endian DEFLATE fields without synthesizing padding past EOF.
    fn take(&mut self, count: usize) -> Option<usize> {
        if self.remaining() < count {
            return None;
        }
        let mut value = 0;
        for shift in 0..count {
            value |=
                usize::from((self.body[self.position / 8] >> (self.position % 8)) & 1) << shift;
            self.position += 1;
        }
        Some(value)
    }

    /// Skips an already validated stored block without allocating its contents.
    fn stored(&mut self) -> Option<()> {
        self.position = (self.position + 7) & !7;
        let length = self.take(16)?;
        if self.take(16)? != length ^ 0xffff || self.remaining() / 8 < length {
            return None;
        }
        self.position += length * 8;
        Some(())
    }
}

struct Huffman {
    counts: [usize; 16],
    first: [usize; 16],
    symbols: Vec<usize>,
    lookahead: usize,
}

impl Huffman {
    /// Builds canonical codes from the wire lengths; symbols stay ordered within each width.
    fn new(lengths: &[usize]) -> Option<Self> {
        let mut counts = [0; 16];
        for &length in lengths {
            *counts.get_mut(length)? += 1;
        }
        counts[0] = 0;
        let mut first = [0; 16];
        for width in 1..16 {
            first[width] = (first[width - 1] + counts[width - 1]) << 1;
            if first[width] + counts[width] > 1 << width {
                return None;
            }
        }
        let symbols = (1..16)
            .flat_map(|width| {
                lengths
                    .iter()
                    .enumerate()
                    .filter_map(move |(symbol, &length)| (length == width).then_some(symbol))
            })
            .collect();
        let lookahead = counts.iter().position(|&count| count != 0).unwrap_or(0);
        Some(Self {
            counts,
            first,
            symbols,
            lookahead,
        })
    }

    /// Reads canonical Huffman bits while preserving the decoder's initial read-ahead requirement.
    fn symbol(&self, bits: &mut Bits<'_>) -> Option<usize> {
        if bits.remaining() < self.lookahead {
            return None;
        }
        let mut code = 0;
        let mut offset = 0;
        for width in 1..16 {
            code = (code << 1) | bits.take(1)?;
            if code >= self.first[width] && code - self.first[width] < self.counts[width] {
                return self.symbols.get(offset + code - self.first[width]).copied();
            }
            offset += self.counts[width];
        }
        None
    }
}

/// Decodes only block structure and reference widths; the original inflater owns output and limits.
fn reference_tail(bits: &mut Bits<'_>) -> Option<bool> {
    loop {
        let final_block = bits.take(1)? != 0;
        let kind = bits.take(2)?;
        let (literals, distances) = match kind {
            0 => {
                bits.stored()?;
                if final_block {
                    return Some(false);
                }
                continue;
            }
            1 => {
                let mut lengths = [8; 288];
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                (Huffman::new(&lengths)?, None)
            }
            2 => {
                let (literals, distances) = dynamic(bits, final_block)?;
                (literals, Some(distances))
            }
            _ => return None,
        };
        loop {
            let symbol = literals.symbol(bits)?;
            match symbol {
                0..=255 => continue,
                256 => break,
                257..=285 => {
                    let extra = if (265..285).contains(&symbol) {
                        (symbol - 261) / 4
                    } else {
                        0
                    };
                    if bits.take(extra).is_none() {
                        return Some(true);
                    }
                    let distance = match &distances {
                        Some(table) => table.symbol(bits)?,
                        None => match bits.take(5) {
                            Some(value) => value.reverse_bits() >> (usize::BITS - 5),
                            None => return Some(true),
                        },
                    };
                    if distance >= 30 {
                        return None;
                    }
                    if bits.take((distance / 2).saturating_sub(1)).is_none() {
                        return Some(true);
                    }
                }
                _ => return None,
            }
        }
        if final_block {
            return Some(false);
        }
    }
}

/// Expands bounded dynamic code lengths and retains their block-specific read-ahead policy.
fn dynamic(bits: &mut Bits<'_>, final_block: bool) -> Option<(Huffman, Huffman)> {
    let literals = bits.take(5)? + 257;
    let distances = bits.take(5)? + 1;
    let codes = bits.take(4)? + 4;
    let order = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut lengths = [0; 19];
    for &symbol in &order[..codes] {
        lengths[symbol] = bits.take(3)?;
    }
    let table = Huffman::new(&lengths)?;
    let mut lengths = Vec::with_capacity(literals + distances);
    while lengths.len() < literals + distances {
        let (value, count) = match table.symbol(bits)? {
            symbol @ 0..=15 => (symbol, 1),
            16 => (*lengths.last()?, bits.take(2)? + 3),
            17 => (0, bits.take(3)? + 3),
            18 => (0, bits.take(7)? + 11),
            _ => return None,
        };
        if count > literals + distances - lengths.len() {
            return None;
        }
        lengths.resize(lengths.len() + count, value);
    }
    let mut literal_table = Huffman::new(&lengths[..literals])?;
    literal_table.lookahead =
        literal_table.lookahead.max(lengths[256]) + if final_block { 0 } else { 10 };
    Some((literal_table, Huffman::new(&lengths[literals..])?))
}
