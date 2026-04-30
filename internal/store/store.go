// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package store manages the .vet/ directory and artifact verification records.
package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultVetDir = ".vet"

// VerificationRecord is written to .vet/records/<artifact-hash>.json
// after a successful vet sign or vet verify operation.
type VerificationRecord struct {
	ArtifactRef   string    `json:"artifact_ref"`
	ArtifactHash  string    `json:"artifact_hash"`
	Signed        bool      `json:"signed"`
	SignerSubject string    `json:"signer_subject,omitempty"`
	RekorLogID   string    `json:"rekor_log_id,omitempty"`
	SLSALevel     int       `json:"slsa_level"`    // 0 = not verified
	SBOMPresent   bool      `json:"sbom_present"`
	CVECritical   bool      `json:"cve_critical"`
	CVEHigh       bool      `json:"cve_high"`
	VerifiedAt    time.Time `json:"verified_at"`
	Source        string    `json:"source,omitempty"` // github.com/org/repo
}

// GateResult is written to .vet/gate-result.json.
// Cedar attribute names match what attest's Cedar PDP reads from context.workload.*
type GateResult struct {
	Artifact     string    `json:"artifact"`
	ArtifactHash string    `json:"artifact_hash"`
	SLSALevel    int       `json:"slsa_level"`
	SBOMPresent  bool      `json:"sbom_present"`
	CVECritical  bool      `json:"cve_critical"`
	CVEHigh      bool      `json:"cve_high"`
	Signed       bool      `json:"signed"`
	PolicyMet    bool      `json:"policy_met"`
	EvaluatedAt  time.Time `json:"evaluated_at"`
}

// Policy is read from .vet/policy.yaml.
type Policy struct {
	MinSLSALevel int      `yaml:"min_slsa_level"` // default 0 (no requirement)
	CVEThreshold string   `yaml:"cve_threshold"`  // "critical", "high", "medium", ""
	AllowedSigningIDs []string `yaml:"allowed_signing_ids,omitempty"`
}

// Store manages the .vet/ directory.
type Store struct {
	dir string
}

// New creates a Store rooted at dir (defaults to .vet if empty).
func New(dir string) *Store {
	if dir == "" {
		dir = defaultVetDir
	}
	return &Store{dir: dir}
}

// Default returns a Store at the default .vet path.
func Default() *Store { return New("") }

// Init creates the .vet/ directory structure.
func (s *Store) Init() error {
	for _, sub := range []string{"records", "sboms"} {
		if err := os.MkdirAll(filepath.Join(s.dir, sub), 0o750); err != nil {
			return fmt.Errorf("create .vet/%s: %w", sub, err)
		}
	}
	return nil
}

// SaveRecord writes a VerificationRecord to .vet/records/<key>.json.
// The key is derived from the artifact reference.
func (s *Store) SaveRecord(r *VerificationRecord) error {
	if err := s.Init(); err != nil {
		return err
	}
	key := recordKey(r.ArtifactRef)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	return os.WriteFile(filepath.Join(s.dir, "records", key+".json"), data, 0o640)
}

// LoadRecord reads .vet/records/<key>.json for the given artifact ref.
// Returns nil, nil if not found.
func (s *Store) LoadRecord(artifactRef string) (*VerificationRecord, error) {
	key := recordKey(artifactRef)
	data, err := os.ReadFile(filepath.Join(s.dir, "records", key+".json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read record: %w", err)
	}
	var r VerificationRecord
	return &r, json.Unmarshal(data, &r)
}

// SaveGateResult writes the gate result to .vet/gate-result.json.
func (s *Store) SaveGateResult(g *GateResult) error {
	if err := s.Init(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal gate result: %w", err)
	}
	return os.WriteFile(filepath.Join(s.dir, "gate-result.json"), data, 0o640)
}

// SBOMPath returns the path for storing an SBOM file.
func (s *Store) SBOMPath(artifactRef, format string) string {
	key := recordKey(artifactRef)
	ext := ".spdx.json"
	if strings.Contains(format, "cyclonedx") {
		ext = ".cyclonedx.json"
	}
	return filepath.Join(s.dir, "sboms", key+ext)
}

// Dir returns the root .vet/ directory path.
func (s *Store) Dir() string { return s.dir }

// recordKey produces a filesystem-safe key from an artifact reference.
func recordKey(ref string) string {
	// Use a short sha256 of the ref for the filename.
	h := sha256.Sum256([]byte(ref))
	return fmt.Sprintf("%x", h[:8])
}
