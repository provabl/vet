// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package cve

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/provabl/vet/internal/sbom"
)

// osvQueryURL is the OSV single-package query endpoint. Unlike /v1/querybatch
// (which returns only vuln IDs), /v1/query returns full vuln records including
// severity inline, so a single call per package yields the CRITICAL/HIGH verdict.
const osvQueryURL = "https://api.osv.dev/v1/query"

// maxOSVPackages bounds how many packages a single scan will query against OSV,
// so a pathologically large SBOM cannot wedge a run. If the set exceeds it, the
// scan still runs over the first maxOSVPackages packages.
const maxOSVPackages = 500

// OSVSource is the default CVE Source: it queries OSV's free API per package.
// It is the path vet has always used for container/binary SBOMs — packages with
// a PURL or an OSV ecosystem (npm, Go, PyPI, …). It is NOT distro-advisory aware:
// Amazon Linux / RHEL packages keyed only by name resolve to nothing useful in
// OSV's "Linux" ecosystem, which is why AMI scanning needs a different Source
// (see package doc + provabl/vet#32).
type OSVSource struct {
	client *http.Client
}

// NewOSVSource returns an OSVSource. A nil client gets a default 30s-timeout one.
func NewOSVSource(client *http.Client) *OSVSource {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &OSVSource{client: client}
}

// Name identifies the source.
func (*OSVSource) Name() string { return "osv" }

// Scan queries OSV for each package and returns the aggregate critical/high
// verdict. Fail-closed: a transport error mid-scan returns an error (the caller
// must not pass), rather than under-reporting. A package OSV cannot resolve (no
// PURL, no ecosystem) is skipped — a bare name is ambiguous across ecosystems —
// but counted as not-scanned so the caller can see coverage.
func (s *OSVSource) Scan(ctx context.Context, pkgs []sbom.Package) (Verdict, error) {
	if len(pkgs) > maxOSVPackages {
		pkgs = pkgs[:maxOSVPackages]
	}
	var v Verdict
	for _, p := range pkgs {
		c, h, resolvable, err := queryOSV(ctx, s.client, p)
		if err != nil {
			return Verdict{}, fmt.Errorf("OSV query failed for %s: %w", pkgIdent(p), err)
		}
		if !resolvable {
			continue
		}
		v.Scanned++
		v.Critical = v.Critical || c
		v.High = v.High || h
	}
	return v, nil
}

func pkgIdent(p sbom.Package) string {
	if p.PURL != "" {
		return p.PURL
	}
	return p.Name + "@" + p.Version
}

// queryOSV asks OSV whether a single package has known critical/high
// vulnerabilities. It queries by PURL when available (PURL encodes the
// ecosystem), else by name+ecosystem. resolvable reports whether OSV could be
// queried for the package at all (false when it has neither a PURL nor an
// ecosystem). A malformed/empty response is treated as "no known vulns"; a
// transport error is returned so the caller can fail closed.
func queryOSV(ctx context.Context, client *http.Client, p sbom.Package) (critical, high, resolvable bool, err error) {
	var body string
	switch {
	case p.PURL != "":
		body = fmt.Sprintf(`{"package":{"purl":%q}}`, p.PURL)
	case p.Ecosystem != "":
		body = fmt.Sprintf(`{"package":{"name":%q,"ecosystem":%q}}`, p.Name, p.Ecosystem)
	default:
		return false, false, false, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewBufferString(body))
	if err != nil {
		return false, false, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, false, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, false, false, fmt.Errorf("OSV returned status %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var result struct {
		Vulns []struct {
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			DatabaseSpecific struct {
				Severity string `json:"severity"`
			} `json:"database_specific"`
		} `json:"vulns"`
	}
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return false, false, true, nil
	}
	for _, vuln := range result.Vulns {
		// Some feeds carry a categorical severity (GHSA: "CRITICAL"/"HIGH"); CVSS
		// feeds carry a vector score in Score. Check both.
		sev := strings.ToUpper(vuln.DatabaseSpecific.Severity)
		if sev == "CRITICAL" {
			critical = true
		}
		if sev == "HIGH" {
			high = true
		}
		for _, sc := range vuln.Severity {
			up := strings.ToUpper(sc.Score + " " + sc.Type)
			if strings.Contains(up, "CRITICAL") {
				critical = true
			}
			if strings.Contains(up, "HIGH") {
				high = true
			}
		}
	}
	return critical, high, true, nil
}
