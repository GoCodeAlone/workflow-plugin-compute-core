package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// PackageArtifactSignaturePayload is the reusable workflow-compute artifact
// tuple. Field order and plugin_id omission preserve its existing JSON hash.
// Callers supply the expected tuple and trusted keys from their own authority;
// this verifier does not validate download policy or authorize installation.
type PackageArtifactSignaturePayload struct {
	Component string `json:"component"`
	PluginID  string `json:"plugin_id,omitempty"`
	Version   string `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
}

// SigningBytes returns the UTF-8 sha256-prefixed CanonicalHash of the tuple,
// not raw JSON bytes. Bootstrap and directive-bound signatures are separate
// signing domains and are not accepted by Verify.
func (p PackageArtifactSignaturePayload) SigningBytes() []byte {
	return []byte(CanonicalHash(p))
}

// Verify checks only the reusable tuple signature. KeyID selects an exact
// trusted map entry, including legacy aliases; it need not be a fingerprint.
// The envelope's Verified flag is never evidence of a valid signature.
func (p PackageArtifactSignaturePayload) Verify(signature SignatureEnvelope, keys map[string]ed25519.PublicKey) error {
	if signature.Algorithm != "ed25519" {
		return errors.New("artifact signature algorithm is unsupported")
	}
	key, ok := keys[signature.KeyID]
	if !ok {
		return errors.New("artifact signature key is not trusted")
	}
	if len(key) != ed25519.PublicKeySize {
		return errors.New("artifact signature public key has invalid size")
	}
	value, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil {
		return fmt.Errorf("artifact signature is not base64: %w", err)
	}
	if !ed25519.Verify(key, p.SigningBytes(), value) {
		return errors.New("artifact signature verification failed")
	}
	return nil
}
