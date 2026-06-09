// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package vetasp

import (
	"crypto/ed25519"
	"fmt"

	"github.com/provabl/evidence/trust"
)

// amKeyID names the attestation-manager key on the Signed evidence node.
const amKeyID = "vet-am-ephemeral"

// EphemeralAM is the kernel's attestation-manager key for one gate evaluation.
// It implements BOTH trust.Signer (the SIG built-in) and trust.Store (spine
// verification during appraisal), backed by a freshly generated ed25519 keypair.
//
// The key is ephemeral on purpose. vet's appraisal is in-process and synchronous
// — Run signs, Appraise verifies, in the same call — so the public half that
// signed the bundle moments earlier is the only key the spine check needs. The
// durable artifact is the lowered gate-result.json, never the evidence bundle,
// so nothing reads this signature after the process exits. A persisted key would
// add a key-management surface for no benefit and would weaken freshness: it
// would let a stale bundle from a prior run verify, which is exactly what the
// nonce+SIG spine exists to prevent. (A named/persisted key earns its place only
// when evidence is stored and appraised out-of-process — a non-goal here.)
type EphemeralAM struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

// NewEphemeralAM generates a fresh attestation-manager keypair.
func NewEphemeralAM() (*EphemeralAM, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("vet: generate AM key: %w", err)
	}
	return &EphemeralAM{priv: priv, pub: pub, keyID: amKeyID}, nil
}

// Sign implements trust.Signer.
func (a *EphemeralAM) Sign(msg []byte) (sig []byte, keyID string, err error) {
	return ed25519.Sign(a.priv, msg), a.keyID, nil
}

// Verify implements trust.Store: it verifies a signature made by this AM's key.
func (a *EphemeralAM) Verify(keyID string, msg, sig []byte) (bool, error) {
	if keyID != a.keyID {
		return false, nil
	}
	return ed25519.Verify(a.pub, msg, sig), nil
}

// Root implements trust.Store. vet brings no external trust roots (its signature
// verification, when wired, is the appraiser's concern via injection), so there
// are none to resolve here.
func (a *EphemeralAM) Root(string) (trust.Root, bool) { return trust.Root{}, false }
