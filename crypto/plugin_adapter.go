package crypto

import (
	"fmt"

	"github.com/xuda1979/pq-chain/plugin"
	"github.com/xuda1979/pq-chain/protocol"
)

// PluginSigner adapts a plugin.Client to the crypto.Signer interface, so
// accelerated plugins are drop-in replacements for the reference signer.
// Only the Sign/keygen path goes through the plugin; verification always
// uses the open-source verifier.
type PluginSigner struct {
	client *plugin.Client
	scheme protocol.SignatureScheme
}

// NewPluginSigner wraps a connected plugin client. It queries the plugin's
// scheme once and refuses mismatches with the requested scheme.
func NewPluginSigner(client *plugin.Client, want protocol.SignatureScheme) (*PluginSigner, error) {
	got, err := client.Scheme()
	if err != nil {
		return nil, fmt.Errorf("crypto: plugin scheme query: %w", err)
	}
	if got != uint8(want) {
		return nil, fmt.Errorf("crypto: plugin implements scheme %d, want %d", got, want)
	}
	return &PluginSigner{client: client, scheme: want}, nil
}

// Scheme implements Signer.
func (p *PluginSigner) Scheme() protocol.SignatureScheme { return p.scheme }

// GenerateKeyPair implements Signer via the plugin RPC.
func (p *PluginSigner) GenerateKeyPair() (PublicKey, PrivateKey, error) {
	pk, sk, err := p.client.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return PublicKey(pk), PrivateKey(sk), nil
}

// Sign implements Signer via the plugin RPC.
func (p *PluginSigner) Sign(sk PrivateKey, msg []byte) (Signature, error) {
	sig, err := p.client.Sign(sk, msg)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Close shuts the plugin process down.
func (p *PluginSigner) Close() error { return p.client.Close() }
