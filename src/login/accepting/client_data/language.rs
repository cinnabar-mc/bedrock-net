//! Acceptance and byte rewrites from golang.org/x/text v0.35.0; see LICENSE-GO.
// Copyright 2013 The Go Authors. All rights reserved.

mod data {
    include!("language_data.rs");
}
use data::*;
use std::ops::Range;

/// Preserves Go's byte comparison even when a rewrite changes an already scanned token.
fn is_alpha(byte: u8) -> bool {
    byte > b'9'
}

/// Finds an ASCII token in a sorted, fixed-width registry.
fn registered(table: &'static str, value: &[u8]) -> Option<&'static str> {
    let width = value.len();
    if width == 0 {
        return None;
    }
    let (mut low, mut high) = (0, table.len() / width);
    while low < high {
        let index = (low + high) / 2;
        match table.as_bytes()[index * width..(index + 1) * width].cmp(value) {
            std::cmp::Ordering::Less => low = index + 1,
            std::cmp::Ordering::Greater => high = index,
            std::cmp::Ordering::Equal => return Some(&table[index * width..(index + 1) * width]),
        }
    }
    None
}

/// Applies the registry's canonical spelling before the scanner resumes.
fn canonical(value: &'static str, aliases: &[(&str, &'static str)]) -> &'static str {
    aliases
        .binary_search_by_key(&value, |&(key, _)| key)
        .map_or(value, |index| aliases[index].1)
}

/// Keeps Go slice offsets, including views into bytes removed from the logical buffer.
struct Scanner {
    bytes: Vec<u8>,
    length: usize,
    token: Range<usize>,
    start: usize,
    end: usize,
    next: usize,
}

impl Scanner {
    /// Copies the input once and normalizes separators before the first scan.
    fn new(value: &str) -> Option<Self> {
        let mut bytes = value.as_bytes().to_vec();
        for byte in &mut bytes {
            if *byte == b'_' {
                *byte = b'-';
            }
        }
        let length = bytes.len();
        bytes.resize(length.max(32), 0);
        let mut scan = Self {
            length,
            bytes,
            token: 0..0,
            start: 0,
            end: 0,
            next: 0,
        };
        scan.scan()?;
        Some(scan)
    }

    /// Borrows the current token from the backing allocation, not the shortened buffer.
    fn token(&self) -> &[u8] {
        &self.bytes[self.token.clone()]
    }

    /// Checks a logical-buffer slice, turning Go's recovered bounds failures into rejection.
    fn range(&self, range: Range<usize>) -> Option<&[u8]> {
        if range.end > self.length {
            return None;
        }
        self.bytes.get(range)
    }

    /// Copies as many bytes as fit, matching Go's copy into the logical buffer.
    fn write(&mut self, start: usize, value: &[u8]) -> Option<()> {
        let count = self.length.checked_sub(start)?.min(value.len());
        self.bytes
            .get_mut(start..start + count)?
            .copy_from_slice(&value[..count]);
        Some(())
    }

    /// Moves a tail with Go's destination-length truncation and returns the copied count.
    fn move_tail(&mut self, from: usize, to: usize) -> Option<usize> {
        let count = self
            .length
            .checked_sub(from)?
            .min(self.length.checked_sub(to)?);
        self.bytes.copy_within(from..from + count, to);
        Some(count)
    }

    /// Lowercases only the range requested by the owning parser phase.
    fn lower(&mut self, start: usize, end: usize) -> Option<()> {
        if start >= end {
            return Some(());
        }
        if end > self.length {
            return None;
        }
        self.bytes.get_mut(start..end)?.make_ascii_lowercase();
        Some(())
    }

    /// Resizes a rewritten range while retaining stale token views as Go slices do.
    fn resize_range(&mut self, start: usize, old_end: usize, size: usize) -> Option<()> {
        self.start = start;
        let end = start.checked_add(size)?;
        if end != old_end {
            // Accepted registry replacements and deduplications never grow a range.
            let removed = old_end.checked_sub(end)?;
            self.range(old_end..self.length)?;
            self.bytes.copy_within(old_end..self.length, end);
            self.length = self.length.checked_sub(removed)?;
            self.next = end.checked_add(self.next.checked_sub(self.end)?)?;
            self.end = end;
        }
        Some(())
    }

    /// Replaces a recognized subtag without changing the current token's slice offsets.
    fn replace(&mut self, value: &str) -> Option<()> {
        self.resize_range(self.start, self.end, value.len())?;
        self.write(self.start, value.as_bytes())
    }

    /// Removes a recognized unspecified subtag and positions the next scan at its start.
    fn gobble(&mut self) -> Option<()> {
        if self.start == 0 {
            self.length = self.move_tail(self.next, 0)?;
            self.end = 0;
        } else {
            let position = self.start - 1;
            self.length = position + self.move_tail(self.end, position)?;
            self.end = self.start - 1;
        }
        self.next = self.start;
        Some(())
    }

    /// Deletes bytes before the current token and shifts cursor positions without rebasing its view.
    fn delete_range(&mut self, start: usize, end: usize) -> Option<()> {
        self.range(start..end)?;
        let removed = end - start;
        self.bytes.copy_within(end..self.length, start);
        self.length -= removed;
        self.next = self.next.checked_sub(removed)?;
        self.start = self.start.checked_sub(removed)?;
        self.end = self.end.checked_sub(removed)?;
        Some(())
    }

    /// Scans one subtag and returns the previous end, rejecting errors Go never clears.
    fn scan(&mut self) -> Option<usize> {
        let previous = self.end;
        self.token = 0..0;
        self.start = self.next;
        if self.next < self.length {
            let rest = self.range(self.next..self.length)?;
            if let Some(offset) = rest.iter().position(|&byte| byte == b'-') {
                self.end = self.next + offset;
                self.next = self.end + 1;
            } else {
                self.end = self.length;
                self.next = self.length;
            }
            let token = self.range(self.start..self.end)?;
            if !(1..=8).contains(&token.len()) || !token.iter().all(u8::is_ascii_alphanumeric) {
                return None;
            }
            self.token = self.start..self.end;
        } else if self.length > 0 && self.bytes[self.length - 1] == b'-' {
            return None;
        }
        Some(previous)
    }

    /// Consumes an extension body whose subtags meet the minimum width.
    fn accept_min_size(&mut self, minimum: usize) -> Option<usize> {
        let mut end = self.end;
        self.scan()?;
        while self.token().len() >= minimum {
            end = self.end;
            self.scan()?;
        }
        Some(end)
    }

    /// Looks up and case-normalizes the current base language or extlang in place.
    fn language(&mut self) -> Option<&'static str> {
        self.bytes[self.token.clone()].make_ascii_lowercase();
        let table = match self.token().len() {
            2 => LANGUAGES_2,
            3 => LANGUAGES_3,
            _ => return None,
        };
        Some(canonical(
            registered(table, self.token())?,
            LANGUAGE_ALIASES,
        ))
    }

    /// Looks up alphabetic or numeric regions and applies the getter's uppercase mutation.
    fn region(&mut self) -> Option<&'static str> {
        self.bytes[self.token.clone()].make_ascii_uppercase();
        let key = self.token().to_ascii_lowercase();
        let table = match key.len() {
            2 => REGIONS_2,
            3 if is_alpha(key[0]) => REGIONS_ALPHA_3,
            3 => REGIONS_NUMERIC_3,
            _ => return None,
        };
        Some(canonical(registered(table, &key)?, REGION_ALIASES))
    }

    /// Validates the script getter's title-case mutation and removes unspecified Zzzz.
    fn script(&mut self) -> Option<()> {
        self.bytes[self.token.clone()].make_ascii_lowercase();
        let script = registered(SCRIPTS, self.token())?;
        self.bytes[self.token.start].make_ascii_uppercase();
        if script == "zzzz" {
            self.gobble()?;
        }
        Some(())
    }

    /// Parses core subtags and performs their byte rewrites before variants and extensions.
    fn tag(&mut self, normalize_extlangs: bool) -> Option<usize> {
        let language = self.language()?;
        self.replace(language)?;
        let language_start = self.start;
        let mut end = self.scan()?;
        while self.token().len() == 3 && is_alpha(self.token()[0]) {
            if normalize_extlangs {
                let language = self.language()?;
                if language != "und" {
                    self.write(language_start, language.as_bytes())?;
                    let separator = language_start + language.len();
                    if separator >= self.length {
                        return None;
                    }
                    self.bytes[separator] = b'-';
                    self.start = separator + 1;
                }
                self.gobble()?;
            }
            end = self.scan()?;
        }
        if self.token().len() == 4 && is_alpha(self.token()[0]) {
            self.script()?;
            end = self.scan()?;
        }
        if (2..=3).contains(&self.token().len()) {
            let region = self.region()?;
            self.replace(region)?;
            end = self.scan()?;
        }
        self.lower(self.start, self.length)?;
        self.variants(end)
    }

    /// Joins live backing-buffer views before a rewrite can change their contents.
    fn join(&self, parts: &[Range<usize>]) -> Option<Vec<u8>> {
        let mut joined = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                joined.push(b'-');
            }
            joined.extend_from_slice(self.bytes.get(part.clone())?);
        }
        Some(joined)
    }

    /// Sorts and deduplicates registered variants, including Go's same-length cursor reset.
    fn variants(&mut self, mut end: usize) -> Option<usize> {
        let start = self.start;
        let mut variants = Vec::new();
        let mut last = None;
        let mut sort = false;
        while self.token().len() >= 4 {
            let index = VARIANTS
                .binary_search_by(|&(name, _)| name.as_bytes().cmp(self.token()))
                .ok()?;
            let rank = VARIANTS[index].1;
            variants.push((rank, self.token.clone()));
            if !sort {
                if last.is_some_and(|last| last >= rank) {
                    sort = true;
                    if variants.len() > 8 {
                        break;
                    }
                } else {
                    last = Some(rank);
                }
            }
            end = self.end;
            self.scan()?;
        }
        if sort {
            variants.sort_unstable_by_key(|&(rank, _)| rank);
            variants.dedup_by_key(|entry| entry.0);
            let parts: Vec<_> = variants.into_iter().map(|(_, part)| part).collect();
            let joined = self.join(&parts)?;
            if joined.is_empty() {
                end = start.checked_sub(1)?;
            } else {
                self.resize_range(start, end, joined.len())?;
                self.write(self.start, &joined)?;
                end = self.end;
            }
        }
        Some(end)
    }

    /// Parses and sorts extensions while preserving token views through each byte mutation.
    fn extensions(&mut self) -> Option<usize> {
        let start = self.start;
        let mut end = self.end;
        let mut extensions = Vec::new();
        let mut private = None;
        while self.token().len() == 1 {
            let extension_start = self.start;
            let singleton = self.token()[0];
            end = self.extension()?;
            let extension = extension_start..end;
            self.bytes.get(extension.clone())?;
            if extension.len() < 3 || (singleton != b'x' && extension.len() < 4) {
                return None;
            }
            if start == extension_start && (singleton == b'x' || self.start == self.length) {
                self.length = end;
                return Some(end);
            } else if singleton == b'x' {
                private = Some(extension);
                break;
            }
            extensions.push(extension);
        }
        extensions.sort_unstable_by_key(|part| self.bytes[part.start]);
        extensions.extend(private);
        let joined = self.join(&extensions)?;
        self.length = start;
        if !extensions.is_empty() {
            let length = start.checked_add(joined.len())?;
            if length > self.bytes.len() {
                self.bytes.resize(length, 0);
            }
            self.bytes.get_mut(start..length)?.copy_from_slice(&joined);
            self.length = length;
        } else if start > 0 {
            self.length = start - 1;
        }
        Some(end)
    }

    /// Parses one extension using the pinned Unicode and transformed-extension owners.
    fn extension(&mut self) -> Option<usize> {
        let start = self.start;
        let mut end = self.end;
        match self.token()[0] {
            b'u' => {
                let attribute_start = end;
                self.scan()?;
                if self.token().len() > 2 {
                    let position = attribute_start + 1;
                    self.next = position;
                    let mut attributes = Vec::new();
                    self.scan()?;
                    while self.token().len() > 2 {
                        attributes.push(self.token.clone());
                        end = self.end;
                        self.scan()?;
                    }
                    attributes.sort_unstable_by(|a, b| {
                        self.bytes[a.start..a.start + 3].cmp(&self.bytes[b.start..b.start + 3])
                    });
                    self.write(position, &self.join(&attributes)?)?;
                }
                self.unicode_keys(end)
            }
            b't' => {
                self.scan()?;
                if (2..=3).contains(&self.token().len()) && is_alpha(self.token()[1]) {
                    end = self.tag(false)?;
                    self.lower(start, end)?;
                }
                while self.token().len() == 2 && !is_alpha(self.token()[1]) {
                    end = self.accept_min_size(3)?;
                }
                Some(end)
            }
            b'x' => self.accept_min_size(1),
            _ => self.accept_min_size(2),
        }
    }

    /// Scans a Unicode key and its type subtags while keeping the byte end before the tail.
    fn unicode_key(&mut self) -> Option<usize> {
        let mut end = self.end;
        self.scan()?;
        while end < self.end && self.token().len() > 2 {
            end = self.end;
            self.scan()?;
        }
        Some(end)
    }

    /// Reorders Unicode keys and deletes equal duplicates before resuming later extensions.
    fn unicode_keys(&mut self, mut end: usize) -> Option<usize> {
        let attribute_end = end;
        let mut last = 0..0;
        while self.token().len() == 2 {
            let key = self.token.clone();
            end = self.unicode_key()?;
            if self.bytes[key.clone()] <= self.bytes[last.clone()] {
                let position = attribute_end + 1;
                self.next = position;
                let mut keys = Vec::new();
                self.scan()?;
                while self.token().len() == 2 {
                    let key_start = self.start;
                    end = self.unicode_key()?;
                    if self.bytes.get(key_start..end)?.len() < 2 {
                        return None;
                    }
                    keys.push(key_start..end);
                }
                keys.sort_by(|a, b| {
                    self.bytes[a.start..a.start + 2].cmp(&self.bytes[b.start..b.start + 2])
                });
                let mut unique: Vec<Range<usize>> = Vec::new();
                for key in keys {
                    if let Some(previous) = unique.last()
                        && self.bytes[previous.start..previous.start + 2]
                            == self.bytes[key.start..key.start + 2]
                    {
                        if self.bytes[previous.clone()] != self.bytes[key] {
                            return None;
                        }
                    } else {
                        unique.push(key);
                    }
                }
                let joined = self.join(&unique)?;
                let rewritten_end = position + joined.len();
                if rewritten_end < end {
                    self.delete_range(rewritten_end, end)?;
                    end = rewritten_end;
                }
                self.write(position, &joined)?;
                break;
            }
            last = key;
        }
        Some(end)
    }

    /// Runs the outer grammar; final display-tag canonicalization does not affect acceptance.
    fn parse(&mut self) -> Option<()> {
        match self.token().len() {
            0 => return None,
            1 => {
                self.lower(0, self.length)?;
                if self.token() != b"x" {
                    return None;
                }
                self.extensions()?;
            }
            2..=3 => {
                let end = self.tag(true)?;
                if self.token().len() == 1 {
                    self.extensions()?;
                } else if end < self.length {
                    return None;
                }
            }
            _ => return None,
        }
        Some(())
    }
}

/// Accepts the pinned Go parser's registry, rewrites, underscores and legacy tags.
pub(super) fn valid_language(value: &str) -> bool {
    if grandfathered(value) {
        return true;
    }
    Scanner::new(value)
        .and_then(|mut scan| scan.parse())
        .is_some()
}

/// Matches Go's padded legacy-tag key, including its rune-to-byte conversion.
fn grandfathered(value: &str) -> bool {
    if value.len() > 11 {
        return false;
    }
    let mut key = [0u8; 11];
    for (index, rune) in value.char_indices() {
        key[index] = match rune {
            '_' => b'-',
            'A'..='Z' => rune.to_ascii_lowercase() as u8,
            _ => rune as u32 as u8,
        };
    }
    GRANDFATHERED.iter().any(|tag| {
        key[..tag.len()] == *tag.as_bytes() && key[tag.len()..].iter().all(|&byte| byte == 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_rewrite_resets_cursor_even_without_a_length_change() {
        let mut scan = Scanner::new("en-fonipa-1901-a").unwrap();
        assert_eq!(scan.tag(true), Some(16));
        assert_eq!(
            (scan.start, scan.end, scan.next, scan.length),
            (3, 16, 16, 16)
        );
        assert_eq!(scan.token(), b"a");
        assert!(scan.extensions().is_some());
    }

    #[test]
    fn unicode_dedup_shifts_cursor_but_retains_the_old_token_view() {
        for (value, token, length, accepted) in [
            ("en-u-ca-ca-x-a-x", b"-".as_slice(), 13, false),
            ("en-u-ca-ca-t-US", b"s".as_slice(), 12, true),
        ] {
            let mut scan = Scanner::new(value).unwrap();
            scan.tag(true).unwrap();
            assert_eq!(scan.extension(), Some(7));
            assert_eq!(
                (scan.start, scan.end, scan.next, scan.length),
                (8, 9, 10, length)
            );
            assert_eq!(scan.token(), token);
            assert_eq!(valid_language(value), accepted);
        }
    }

    #[test]
    fn registries_are_sorted_fixed_width_and_replacements_never_grow() {
        for (table, width) in [
            (LANGUAGES_2, 2),
            (LANGUAGES_3, 3),
            (SCRIPTS, 4),
            (REGIONS_2, 2),
            (REGIONS_ALPHA_3, 3),
            (REGIONS_NUMERIC_3, 3),
        ] {
            assert!(table.is_ascii());
            assert_eq!(table.len() % width, 0);
            let entries: Vec<_> = table.as_bytes().chunks_exact(width).collect();
            assert!(entries.windows(2).all(|pair| pair[0] < pair[1]));
        }
        for aliases in [LANGUAGE_ALIASES, REGION_ALIASES] {
            assert!(aliases.windows(2).all(|pair| pair[0].0 < pair[1].0));
            assert!(aliases.iter().all(|(key, value)| value.len() <= key.len()));
        }
    }
}
