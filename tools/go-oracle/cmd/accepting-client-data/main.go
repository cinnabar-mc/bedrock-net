// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Command accepting-client-data regenerates the pinned accepting login tables.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/language"
)

const (
	goVersion   = "go1.26.1"
	textModule  = "golang.org/x/text"
	textVersion = "v0.35.0"
	textSum     = "h1:JOVx6vVDFokkpaq1AEptVzLTpDe9KGpj5tR4/X+ybL8="
)

// main requires an explicit output directory and reports generation failures.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: accepting-client-data DIR")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// moduleDirectory verifies the compiled and selected dependency before reading its source.
func moduleDirectory() (string, error) {
	if runtime.Version() != goVersion || unicode.Version != "15.0.0" {
		return "", fmt.Errorf("require %s with Unicode 15.0.0", goVersion)
	}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("missing Go build information")
	}
	compiled := false
	for _, dep := range build.Deps {
		if dep.Path == textModule {
			compiled = dep.Version == textVersion && dep.Sum == textSum && dep.Replace == nil
		}
	}
	if !compiled {
		return "", fmt.Errorf("require compiled %s %s without replacement and with pinned checksum", textModule, textVersion)
	}
	data, err := exec.Command("go", "list", "-mod=readonly", "-m", "-json", textModule).Output()
	if err != nil {
		return "", fmt.Errorf("list locale module: %w", err)
	}
	var selected struct {
		Path, Version, Sum, Dir string
		Replace                 *json.RawMessage
	}
	if err := json.Unmarshal(data, &selected); err != nil {
		return "", fmt.Errorf("decode locale module: %w", err)
	}
	if selected.Path != textModule || selected.Version != textVersion || selected.Sum != textSum || selected.Replace != nil || selected.Dir == "" {
		return "", fmt.Errorf("require selected %s %s without replacement and with pinned checksum", textModule, textVersion)
	}
	return selected.Dir, nil
}

// sourceMap reads a nonempty named literal map from the pinned module.
func sourceMap(root, file, name string) (*ast.CompositeLit, error) {
	tree, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, "internal/language", file), nil, 0)
	if err != nil {
		return nil, err
	}
	var found *ast.CompositeLit
	for _, declaration := range tree.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != name {
				continue
			}
			if found != nil || len(value.Values) != 1 {
				return nil, fmt.Errorf("unexpected %s declaration", name)
			}
			found, ok = value.Values[0].(*ast.CompositeLit)
			if !ok || len(found.Elts) == 0 {
				return nil, fmt.Errorf("expected nonempty %s literal", name)
			}
		}
	}
	if found == nil {
		return nil, fmt.Errorf("missing %s declaration", name)
	}
	return found, nil
}

// literalText decodes a quoted source literal of the expected kind.
func literalText(expression ast.Expr, kind token.Token) (string, error) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != kind {
		return "", fmt.Errorf("expected %s literal", kind)
	}
	return strconv.Unquote(literal.Value)
}

// sourceRegistries reads variant ranks and grandfathered tags without reconstructing their order.
func sourceRegistries(root string) (map[string]uint64, []string, error) {
	variants := map[string]uint64{}
	var grand []string
	for _, spec := range []struct{ file, name string }{{"tables.go", "variantIndex"}, {"lookup.go", "grandfatheredMap"}} {
		literal, err := sourceMap(root, spec.file, spec.name)
		if err != nil {
			return nil, nil, err
		}
		for _, element := range literal.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok {
				return nil, nil, fmt.Errorf("unexpected %s entry", spec.name)
			}
			if spec.name == "variantIndex" {
				key, err := literalText(pair.Key, token.STRING)
				if err != nil {
					return nil, nil, err
				}
				number, ok := pair.Value.(*ast.BasicLit)
				if !ok || number.Kind != token.INT {
					return nil, nil, fmt.Errorf("unexpected variant rank")
				}
				rank, err := strconv.ParseUint(number.Value, 0, 8)
				if err != nil {
					return nil, nil, err
				}
				variants[key] = rank
			} else {
				array, ok := pair.Key.(*ast.CompositeLit)
				if !ok {
					return nil, nil, fmt.Errorf("unexpected grandfathered tag")
				}
				var key strings.Builder
				for _, element := range array.Elts {
					value, err := literalText(element, token.CHAR)
					if err != nil || len(value) != 1 || value[0] >= 0x80 {
						return nil, nil, fmt.Errorf("unexpected grandfathered tag byte")
					}
					key.WriteString(value)
				}
				grand = append(grand, key.String())
			}
		}
	}
	sort.Strings(grand)
	return variants, grand, nil
}

// registry enumerates fixed-width parser acceptance and canonical replacements.
func registry(kind string, width int) (string, map[string]string, error) {
	total := 1
	for range width {
		total *= 26
	}
	if kind == "numeric" {
		total = 1000
	}
	var keys strings.Builder
	aliases := map[string]string{}
	for n := range total {
		var key string
		if kind == "numeric" {
			key = fmt.Sprintf("%03d", n)
		} else {
			word, value := make([]byte, width), n
			for i := width - 1; i >= 0; i-- {
				word[i] = byte(value%26) + 'a'
				value /= 26
			}
			key = string(word)
		}
		var canonical string
		var err error
		switch kind {
		case "language":
			var value language.Base
			value, err = language.ParseBase(key)
			canonical = value.String()
		case "script":
			var value language.Script
			value, err = language.ParseScript(key)
			canonical = value.String()
		default:
			var value language.Region
			value, err = language.ParseRegion(key)
			canonical = value.String()
		}
		if err != nil {
			continue
		}
		if len(canonical) > len(key) {
			return "", nil, fmt.Errorf("accepted registry replacement grows: %s", key)
		}
		keys.WriteString(key)
		if canonical != key {
			aliases[key] = canonical
		}
	}
	return keys.String(), aliases, nil
}

// emitAliases writes canonical replacements in sorted rows of three entries.
func emitAliases(out *strings.Builder, name string, aliases map[string]string) {
	keys := make([]string, 0, len(aliases))
	for key := range aliases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintf(out, "#[rustfmt::skip]\npub(super) const %s: &[(&str, &str)] = &[\n", name)
	for index, key := range keys {
		if index%3 == 0 {
			out.WriteString("    ")
		}
		fmt.Fprintf(out, "(%q, %q),", key, aliases[key])
		if index%3 == 2 || index == len(keys)-1 {
			out.WriteByte('\n')
		} else {
			out.WriteByte(' ')
		}
	}
	out.WriteString("];\n")
}

// languageData emits complete locale registries and their canonical replacements.
func languageData(root string) (string, error) {
	variants, grand, err := sourceRegistries(root)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString("// Generated by tools/go-oracle/cmd/accepting-client-data; do not edit.\n// Generated from golang.org/x/text v0.35.0 using Go 1.26.1. See LICENSE-GO.\n// Copyright 2013 The Go Authors. All rights reserved.\n")
	languages, regions := map[string]string{}, map[string]string{}
	for _, spec := range []struct {
		name, kind string
		width      int
	}{{"LANGUAGES_2", "language", 2}, {"LANGUAGES_3", "language", 3}, {"SCRIPTS", "script", 4}, {"REGIONS_2", "region", 2}, {"REGIONS_ALPHA_3", "region", 3}, {"REGIONS_NUMERIC_3", "numeric", 3}} {
		keys, aliases, err := registry(spec.kind, spec.width)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&out, "pub(super) const %s: &str = %q;\n", spec.name, keys)
		for key, value := range aliases {
			if spec.kind == "language" {
				languages[key] = value
			} else if spec.kind != "script" {
				regions[key] = value
			}
		}
	}
	emitAliases(&out, "LANGUAGE_ALIASES", languages)
	emitAliases(&out, "REGION_ALIASES", regions)
	keys := make([]string, 0, len(variants))
	for key := range variants {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out.WriteString("pub(super) const VARIANTS: &[(&str, u8)] = &[\n")
	for _, key := range keys {
		fmt.Fprintf(&out, "    (%q, %d),\n", key, variants[key])
	}
	out.WriteString("];\npub(super) const GRANDFATHERED: &[&str] = &[\n")
	for _, key := range grand {
		fmt.Fprintf(&out, "    %q,\n", key)
	}
	out.WriteString("];\n")
	return out.String(), nil
}

// nameLetters emits contiguous Unicode letter ranges and the Rust membership helper.
func nameLetters() string {
	var out strings.Builder
	out.WriteString("//! Unicode 15.0 letter membership from Go 1.26.1; see LICENSE-GO.\n// Generated by tools/go-oracle/cmd/accepting-client-data; do not edit.\n// Copyright 2009 The Go Authors. All rights reserved.\n\n/// Matches an ASCII space or any pinned Unicode letter anywhere in the name.\npub(super) fn contains_letter_or_space(value: &str) -> bool {\n    value.chars().any(|value| {\n        let point = u32::from(value);\n        let index = LETTER_RANGES.partition_point(|&(start, _)| start <= point);\n        value == ' ' || (index > 0 && point <= LETTER_RANGES[index - 1].1)\n    })\n}\n\n#[rustfmt::skip]\nconst LETTER_RANGES: &[(u32, u32)] = &[\n")
	count := 0
	for point := rune(0); point <= unicode.MaxRune; point++ {
		if !unicode.IsLetter(point) {
			continue
		}
		start := point
		for point < unicode.MaxRune && unicode.IsLetter(point+1) {
			point++
		}
		if count%4 == 0 {
			out.WriteString("    ")
		}
		fmt.Fprintf(&out, "(0x%x, 0x%x),", start, point)
		count++
		if count%4 == 0 || point == unicode.MaxRune {
			out.WriteByte('\n')
		} else {
			out.WriteByte(' ')
		}
	}
	return strings.TrimRight(out.String(), " \n") + "\n];\n"
}

// run verifies the pins and generates both files before writing either output.
func run(destination string) error {
	root, err := moduleDirectory()
	if err != nil {
		return err
	}
	locale, err := languageData(root)
	if err != nil {
		return err
	}
	for _, file := range []struct{ name, data string }{{"language_data.rs", locale}, {"name_letters.rs", nameLetters()}} {
		if err := os.WriteFile(filepath.Join(destination, file.name), []byte(file.data), 0o644); err != nil {
			return err
		}
	}
	return nil
}
