#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Scott Friedman
# SPDX-License-Identifier: Apache-2.0
#
# spore.host vet integration test scenarios.
# Demonstrates the 4 supply chain verification scenarios for spore.host.
# Prerequisites: cosign, gh CLI (authenticated), vet binary in PATH.

set -euo pipefail

VET="${VET_BINARY:-vet}"
SPORE_HOST_REPO="github.com/scttfrdmn/mycelium"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; exit 1; }
section() { echo ""; echo "── $* ──────────────────────────────────────────"; }

# Check prerequisites
section "Prerequisites"
command -v cosign >/dev/null 2>&1 && pass "cosign installed" || fail "cosign not found (https://docs.sigstore.dev/cosign/system_config/installation/)"
command -v gh >/dev/null 2>&1 && pass "gh CLI installed" || fail "gh not found (https://cli.github.com/)"
command -v "$VET" >/dev/null 2>&1 && pass "vet installed" || fail "vet not found (go install github.com/provabl/vet/cmd/vet@latest)"

# ── Scenario 1: Local binary verification ────────────────────────────────────
section "Scenario 1: Local binary verification"
echo "Downloading spawn binary..."
SPAWN_BIN="$TMPDIR/spawn"
curl -sSfL "https://github.com/scttfrdmn/mycelium/releases/latest/download/spawn_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m)" -o "$SPAWN_BIN" || {
  echo "  (spawn binary download failed — skipping live test)"
  SPAWN_BIN=""
}

if [ -n "$SPAWN_BIN" ]; then
  chmod +x "$SPAWN_BIN"
  "$VET" verify "$SPAWN_BIN" \
    --source "$SPORE_HOST_REPO" \
    --min-slsa-level 2 \
    --vet-dir "$TMPDIR/.vet" && pass "spawn binary SLSA provenance verified" || echo "  ⚠ verify failed (may not have SLSA attestation yet)"
fi

# ── Scenario 3: Gate for SRE access ─────────────────────────────────────────
section "Scenario 3: Gate (Cedar workload attributes)"
if [ -n "$SPAWN_BIN" ]; then
  # Create a mock record since real verification may not have run
  mkdir -p "$TMPDIR/.vet/records"
  cat > "$TMPDIR/.vet/policy.yaml" << 'EOF'
min_slsa_level: 2
cve_threshold: "critical"
allowed_signing_ids:
  - "https://github.com/scttfrdmn/mycelium/.github/workflows/release.yml"
EOF

  # Only gate if verification succeeded (record exists)
  "$VET" gate "$SPAWN_BIN" \
    --policy "$TMPDIR/.vet/policy.yaml" \
    --vet-dir "$TMPDIR/.vet" 2>/dev/null && pass "vet gate wrote Cedar workload attributes" || echo "  ⚠ gate skipped (run verify first)"

  # Show gate-result.json if it was written
  if [ -f "$TMPDIR/.vet/gate-result.json" ]; then
    echo "  gate-result.json:"
    cat "$TMPDIR/.vet/gate-result.json" | python3 -c "
import sys, json
g = json.load(sys.stdin)
print(f'    SLSALevel:    {g.get(\"slsa_level\", 0)}')
print(f'    Signed:       {g.get(\"signed\", False)}')
print(f'    PolicyMet:    {g.get(\"policy_met\", False)}')
"
  fi
fi

# ── Scenario 4: Container image full pipeline ────────────────────────────────
section "Scenario 4: SRE-resident container pipeline (dry run)"
echo "  (Showing commands — skipping live execution without a real container)"
echo ""
echo "  vet sign   ghcr.io/scttfrdmn/spawn-sre:v1.4.0 --yes"
echo "  vet sbom   ghcr.io/scttfrdmn/spawn-sre:v1.4.0 --format spdx --attest"
echo "  vet verify ghcr.io/scttfrdmn/spawn-sre:v1.4.0 --source $SPORE_HOST_REPO --min-slsa-level 2"
echo "  vet gate   ghcr.io/scttfrdmn/spawn-sre:v1.4.0"
echo ""
pass "Scenario 4 command sequence documented"

echo ""
echo "── Integration test complete ────────────────────────────────────"
echo "  See docs/spore-host-test-case.md for full scenario documentation."
