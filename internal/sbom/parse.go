// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Package is the minimal identity of a software component extracted from an SBOM,
// enough to query a vulnerability database. PURL is preferred when present (it
// encodes the ecosystem); Name/Version/Ecosystem are the fallback.
type Package struct {
	Name      string
	Version   string
	Ecosystem string // OSV ecosystem (e.g. "npm", "Go", "PyPI"), when derivable
	PURL      string // package URL, e.g. "pkg:golang/github.com/foo/bar@v1.2.3"
}

// ErrNoSBOM is returned by Load when the SBOM file does not exist.
var ErrNoSBOM = errors.New("no SBOM file")

// ErrEmptySBOM is returned by Parse when the document is valid but lists no
// packages — a valid SBOM with nothing to check is treated distinctly from a
// missing one.
var ErrEmptySBOM = errors.New("SBOM contains no packages")

// Load reads and parses the SBOM at path. It returns ErrNoSBOM (wrapped) when the
// file is absent so callers can distinguish "no SBOM" from "bad SBOM".
func Load(path string) ([]Package, error) {
	data, err := os.ReadFile(path) // #nosec G304 — store-derived path
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrNoSBOM, path)
	}
	if err != nil {
		return nil, fmt.Errorf("read SBOM %s: %w", path, err)
	}
	return parse(data, path)
}

// Parse decodes raw SBOM bytes (origin is used only for error messages).
func Parse(raw []byte, origin string) ([]Package, error) { return parse(raw, origin) }

func parse(data []byte, origin string) ([]Package, error) {
	// Sniff the format by content. syft writes either SPDX-JSON (has "spdxVersion")
	// or CycloneDX-JSON (has "bomFormat":"CycloneDX").
	switch {
	case bytes.Contains(data, []byte(`"spdxVersion"`)):
		return parseSPDX(data, origin)
	case bytes.Contains(data, []byte(`"bomFormat"`)) && bytes.Contains(data, []byte("CycloneDX")):
		return parseCycloneDX(data, origin)
	default:
		return nil, fmt.Errorf("unrecognized SBOM format in %s (not SPDX-JSON or CycloneDX-JSON)", origin)
	}
}

// --- SPDX-JSON ---------------------------------------------------------------

type spdxDoc struct {
	Packages []struct {
		Name         string `json:"name"`
		VersionInfo  string `json:"versionInfo"`
		ExternalRefs []struct {
			ReferenceType     string `json:"referenceType"`
			ReferenceCategory string `json:"referenceCategory"`
			ReferenceLocator  string `json:"referenceLocator"`
		} `json:"externalRefs"`
	} `json:"packages"`
}

func parseSPDX(data []byte, origin string) ([]Package, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX SBOM %s: %w", origin, err)
	}
	var out []Package
	for _, p := range doc.Packages {
		pkg := Package{Name: p.Name, Version: p.VersionInfo}
		for _, ref := range p.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				pkg.PURL = ref.ReferenceLocator
				pkg.Ecosystem = ecosystemFromPURL(ref.ReferenceLocator)
				break
			}
		}
		if pkg.Name == "" && pkg.PURL == "" {
			continue
		}
		out = append(out, pkg)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptySBOM, origin)
	}
	return out, nil
}

// --- CycloneDX-JSON ----------------------------------------------------------

type cycloneDoc struct {
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

func parseCycloneDX(data []byte, origin string) ([]Package, error) {
	var doc cycloneDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CycloneDX SBOM %s: %w", origin, err)
	}
	var out []Package
	for _, c := range doc.Components {
		if c.Name == "" && c.PURL == "" {
			continue
		}
		out = append(out, Package{
			Name:      c.Name,
			Version:   c.Version,
			PURL:      c.PURL,
			Ecosystem: ecosystemFromPURL(c.PURL),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptySBOM, origin)
	}
	return out, nil
}

// ecosystemFromPURL maps a package URL's type to an OSV ecosystem name. Returns
// "" when the purl is absent or the type is unmapped (the OSV query then falls
// back to a purl-only query, which OSV resolves itself).
func ecosystemFromPURL(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	typ := rest
	if i := strings.IndexAny(rest, "/@"); i != -1 {
		typ = rest[:i]
	}
	switch strings.ToLower(typ) {
	case "golang":
		return "Go"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "gem":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "composer":
		return "Packagist"
	case "apk":
		return "Alpine"
	case "deb":
		return "Debian"
	default:
		return ""
	}
}
