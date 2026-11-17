package resolver

import (
	"fmt"
	"slices"
	"strings"
)

// Source is a kind of project data a repository can be resolved from.
type Source string

const (
	// SourceVCS is an external reference of type "vcs". BOM uploads set it,
	// from the BOM's metadata.component.
	SourceVCS Source = "vcs"
	// SourceProperty is the github/repo project property. Setting it requires
	// the PORTFOLIO_MANAGEMENT permission.
	SourceProperty Source = "property"
	// SourcePURL is a pkg:github project PURL. BOM uploads set it, from the
	// BOM's metadata.component.
	SourcePURL Source = "purl"
)

// AllSources are the sources consulted by default, in order.
var AllSources = []Source{SourceVCS, SourceProperty, SourcePURL}

// ParseSources parses a comma-separated list of sources, e.g. "vcs,property".
func ParseSources(s string) ([]Source, error) {
	var sources []Source
	for _, name := range strings.Split(s, ",") {
		src := Source(strings.ToLower(strings.TrimSpace(name)))
		if src == "" {
			continue
		}
		if !slices.Contains(AllSources, src) {
			return nil, fmt.Errorf("unknown repository source %q: want vcs, property or purl", name)
		}
		if !slices.Contains(sources, src) {
			sources = append(sources, src)
		}
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("no repository sources")
	}
	return sources, nil
}
