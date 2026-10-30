// SPDX-License-Identifier: MIT
// Command builtin-packs exports the selected Gophertunnel built-in pack catalog.
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
	"runtime/debug"
	"strconv"

	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
)

const baselineModule = "github.com/sandertv/gophertunnel"

type module struct {
	Path, Version, Sum, Dir string
	Replace                 *module
}

type pack struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// main requires an explicit destination and keeps diagnostics out of the generated document.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: builtin-packs FILE")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// selectedModule binds the source being read to the actual dependency compiled into this tool.
func selectedModule() (module, error) {
	data, err := exec.Command("go", "list", "-mod=readonly", "-m", "-json", baselineModule).Output()
	if err != nil {
		return module{}, fmt.Errorf("list built-in pack baseline: %w", err)
	}
	var selected module
	if err := json.Unmarshal(data, &selected); err != nil {
		return module{}, fmt.Errorf("decode built-in pack baseline: %w", err)
	}
	if selected.Path != baselineModule {
		return module{}, fmt.Errorf("unexpected built-in pack module")
	}
	if selected.Replace != nil {
		selected = *selected.Replace
	}
	if selected.Dir == "" || selected.Version == "" || selected.Sum == "" || selected.Replace != nil {
		return module{}, fmt.Errorf("built-in pack baseline requires a checksum-pinned module version")
	}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return module{}, fmt.Errorf("missing Go build information")
	}
	for _, dependency := range build.Deps {
		if dependency.Path != baselineModule {
			continue
		}
		if dependency.Replace != nil {
			dependency = dependency.Replace
		}
		if dependency.Path == selected.Path && dependency.Version == selected.Version && dependency.Sum == selected.Sum {
			return selected, nil
		}
	}
	return module{}, fmt.Errorf("selected built-in pack module differs from the compiled baseline")
}

// sourcePacks reads the complete ordered exemption literal and refuses an unrecognized layout.
func sourcePacks(source []byte) ([]pack, error) {
	tree, err := parser.ParseFile(token.NewFileSet(), "conn.go", source, 0)
	if err != nil {
		return nil, err
	}
	var packs []pack
	found := false
	for _, declaration := range tree.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, specification := range general.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "exemptedPacks" {
				continue
			}
			if found || len(value.Values) != 1 {
				return nil, fmt.Errorf("unexpected exemption declaration")
			}
			found = true
			list, ok := value.Values[0].(*ast.CompositeLit)
			if !ok || len(list.Elts) == 0 {
				return nil, fmt.Errorf("expected a nonempty exemption literal")
			}
			for _, element := range list.Elts {
				entry, ok := element.(*ast.CompositeLit)
				if !ok || len(entry.Elts) != 2 {
					return nil, fmt.Errorf("unexpected built-in pack entry")
				}
				fields := make(map[string]string, 2)
				for _, field := range entry.Elts {
					pair, ok := field.(*ast.KeyValueExpr)
					if !ok {
						return nil, fmt.Errorf("expected named built-in pack fields")
					}
					name, ok := pair.Key.(*ast.Ident)
					if !ok || (name.Name != "uuid" && name.Name != "version") {
						return nil, fmt.Errorf("unexpected built-in pack field")
					}
					literal, ok := pair.Value.(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING || fields[name.Name] != "" {
						return nil, fmt.Errorf("expected unique built-in pack string fields")
					}
					text, err := strconv.Unquote(literal.Value)
					if err != nil || text == "" {
						return nil, fmt.Errorf("invalid built-in pack string field")
					}
					fields[name.Name] = text
				}
				if len(fields) != 2 {
					return nil, fmt.Errorf("missing built-in pack field")
				}
				packs = append(packs, pack{fields["uuid"], fields["version"]})
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("missing exemption declaration")
	}
	return packs, nil
}

// run preserves source order while checking every extracted identity against the compiled owner.
func run(destination string) error {
	selected, err := selectedModule()
	if err != nil {
		return err
	}
	source, err := os.ReadFile(filepath.Join(selected.Dir, "minecraft", "conn.go"))
	if err != nil {
		return fmt.Errorf("read built-in pack baseline: %w", err)
	}
	packs, err := sourcePacks(source)
	if err != nil {
		return err
	}
	identities := make(map[pack]bool, len(packs))
	for _, entry := range packs {
		id, err := uuid.Parse(entry.ID)
		if err != nil || id.String() != entry.ID || identities[entry] {
			return fmt.Errorf("invalid or duplicate built-in pack identity")
		}
		identities[entry] = true
		if !minecraft.IsBuiltinResourcePack(entry.ID, entry.Version) || minecraft.IsBuiltinResourcePack(entry.ID, entry.Version+".invalid") {
			return fmt.Errorf("extracted built-in pack differs from the compiled exemption policy")
		}
	}
	data, err := json.MarshalIndent(struct {
		ProtocolVersion       int    `json:"protocol_version"`
		BaselineModuleVersion string `json:"baseline_module_version"`
		Packs                 []pack `json:"packs"`
	}{protocol.CurrentProtocol, selected.Version, packs}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destination, append(data, '\n'), 0o644)
}
