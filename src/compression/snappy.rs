//! Bounded Snappy match search for independent 64 KiB blocks.
// The match search follows rust-snappy's BSD-3-Clause encoder; see THIRD_PARTY_NOTICES.md.

const BLOCK: usize = 65536;
const HASH_BITS: u32 = 14;

pub(super) struct Encoder {
    table: Box<[u16; 1 << HASH_BITS]>,
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            table: Box::new([0; 1 << HASH_BITS]),
        }
    }
}

impl Encoder {
    /// Writes one raw Snappy stream into a caller-owned maximum-sized buffer.
    pub(super) fn compress(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, snap::Error> {
        let maximum = snap::raw::max_compress_len(input.len());
        if maximum == 0 {
            return Err(snap::Error::TooBig {
                given: input.len() as u64,
                max: u32::MAX as u64,
            });
        }
        if output.len() < maximum {
            return Err(snap::Error::BufferTooSmall {
                given: output.len() as u64,
                min: maximum as u64,
            });
        }
        let mut out = Writer {
            bytes: output,
            position: 0,
        };
        let mut length = input.len() as u32;
        while length >= 128 {
            out.byte(length as u8 | 128);
            length >>= 7;
        }
        out.byte(length as u8);
        for block in input.chunks(BLOCK) {
            self.block(block, &mut out);
        }
        Ok(out.position)
    }

    /// Emits literals between matches, skipping more probes through incompressible spans.
    #[inline(always)]
    fn block(&mut self, input: &[u8], out: &mut Writer<'_>) {
        self.table.fill(0);
        let limit = input.len().saturating_sub(15);
        let (mut position, mut literal, mut skip) = (1, 0, 128);
        while position < limit {
            let word = word(input, position);
            let hash = (word.wrapping_mul(0xcf1b_bcdc_bfa5_4001) >> (64 - HASH_BITS)) as usize;
            let candidate = usize::from(self.table[hash]);
            self.table[hash] = position as u16;
            if word != self::word(input, candidate) {
                let step = skip >> 5;
                position += step;
                skip += step;
                continue;
            }
            out.literal(&input[literal..], position - literal);
            let end = match_end(input, position + 8, candidate + 8);
            out.copy(position - candidate, end - position);
            position = end;
            literal = end;
            skip = 128;
        }
        out.literal(&input[literal..], input.len() - literal);
    }
}

/// Reads one search key after the block's retained lookahead has been checked.
#[inline(always)]
fn word(input: &[u8], position: usize) -> u64 {
    u64::from_le_bytes(input[position..position + 8].try_into().unwrap())
}

/// Extends a checked match without reading beyond the independent input block.
#[inline(always)]
fn match_end(input: &[u8], mut end: usize, mut source: usize) -> usize {
    while end + 8 <= input.len() {
        let a = u64::from_le_bytes(input[end..end + 8].try_into().unwrap());
        let b = u64::from_le_bytes(input[source..source + 8].try_into().unwrap());
        let different = a ^ b;
        if different != 0 {
            return end + different.trailing_zeros() as usize / 8;
        }
        end += 8;
        source += 8;
    }
    while end < input.len() && input[end] == input[source] {
        end += 1;
        source += 1;
    }
    end
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl Writer<'_> {
    /// Appends one byte within Snappy's prevalidated maximum output size.
    #[inline(always)]
    fn byte(&mut self, byte: u8) {
        self.bytes[self.position] = byte;
        self.position += 1;
    }

    /// Emits one nonempty literal with the shortest legal length representation.
    #[inline(always)]
    fn literal(&mut self, input: &[u8], count: usize) {
        if count == 0 {
            return;
        }
        let length = count - 1;
        if length < 60 {
            self.byte((length as u8) << 2);
        } else if length < 256 {
            self.bytes[self.position..self.position + 2].copy_from_slice(&[60 << 2, length as u8]);
            self.position += 2;
        } else {
            self.bytes[self.position..self.position + 3].copy_from_slice(&[
                61 << 2,
                length as u8,
                (length >> 8) as u8,
            ]);
            self.position += 3;
        }
        // Snappy's maximum output allowance includes slack for this short literal store.
        if count <= 16 && input.len() >= 16 {
            self.bytes[self.position..self.position + 16].copy_from_slice(&input[..16]);
        } else {
            self.bytes[self.position..self.position + count].copy_from_slice(&input[..count]);
        }
        self.position += count;
    }

    /// Splits a block-local match into legal one- or two-byte-offset copy commands.
    #[inline(always)]
    fn copy(&mut self, offset: usize, mut length: usize) {
        while length >= 68 {
            self.copy_chunk(offset, 64);
            length -= 64;
        }
        if length > 64 {
            self.copy_chunk(offset, 60);
            length -= 60;
        }
        self.copy_chunk(offset, length);
    }

    /// Writes a single copy tag for a previously checked block-local match.
    #[inline(always)]
    fn copy_chunk(&mut self, offset: usize, count: usize) {
        if offset < 2048 && count < 12 {
            self.bytes[self.position..self.position + 2].copy_from_slice(&[
                1 | (((count - 4) as u8) << 2) | ((offset >> 8) as u8) << 5,
                offset as u8,
            ]);
            self.position += 2;
        } else {
            self.bytes[self.position..self.position + 3].copy_from_slice(&[
                2 | (((count - 1) as u8) << 2),
                offset as u8,
                (offset >> 8) as u8,
            ]);
            self.position += 3;
        }
    }
}
