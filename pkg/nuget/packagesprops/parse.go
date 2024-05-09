package packagesprops

import (
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	ftypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type Pkg struct {
	Version            string `xml:"Version,attr"`
	UpdatePackageName  string `xml:"Update,attr"`
	IncludePackageName string `xml:"Include,attr"`
}

// https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L150
type itemGroup struct {
	PackageReferenceEntry []Pkg `xml:"PackageReference"`
	PackageVersionEntry   []Pkg `xml:"PackageVersion"`
}

type project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p Pkg) Package() ftypes.Library {
	// Update attribute is considered legacy, so preferring Include
	name := p.UpdatePackageName
	if p.IncludePackageName != "" {
		name = p.IncludePackageName
	}

	name = strings.TrimSpace(name)
	version := strings.TrimSpace(p.Version)
	return ftypes.Library{
		ID:      utils.ID(ftypes.NuGet, name, version),
		Name:    name,
		Version: version,
	}
}

func shouldSkipPkg(pkg ftypes.Library) bool {
	if pkg.Name == "" || pkg.Version == "" {
		return true
	}
	// *packages.props files don't contain variable resolution information.
	// So we need to skip them.
	if isVariable(pkg.Name) || isVariable(pkg.Version) {
		return true
	}
	return false
}

func isVariable(s string) bool {
	return strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")")
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]ftypes.Library, []ftypes.Dependency, error) {
	var configData project
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}

	var pkgs []ftypes.Library
	for _, item := range configData.ItemGroups {
		for _, pkg := range append(item.PackageReferenceEntry, item.PackageVersionEntry...) {
			pkg := pkg.Package()
			if !shouldSkipPkg(pkg) {
				pkgs = append(pkgs, pkg)
			}
		}
	}
	return utils.UniqueLibraries(pkgs), nil, nil
}
