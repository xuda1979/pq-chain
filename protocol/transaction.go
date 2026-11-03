package protocol

import "errors"

// Transaction kinds.
const (
	// TxTransfer moves native tokens from sender to recipient.
	TxTransfer uint8 = 1
	// TxStake locks tokens to enter the validator set.
	TxStake uint8 = 2
	// TxUnstake unlocks staked tokens (subject to unbonding delay).
	TxUnstake uint8 = 3
)

// Transaction is the canonical on-chain transaction. The signature is
// computed over SignBytes(t), never over the struct as-is.
type Transaction struct {
	// Sender is the address of the signing account.
	Sender Address
	// Nonce is the per-account sequence number (prevents replay).
	Nonce uint64
	// Kind selects the transaction payload type.
	Kind uint8
	// To is the recipient (zero for stake/unstake to self).
	To Address
	// Amount is the value in the smallest unit (1e-9 PQ).
	Amount uint64
	// Fee is the fee offered to the block proposer.
	Fee uint64
	// Payload carries kind-specific data (e.g. stake public key).
	Payload []byte
	// SigScheme identifies the signature algorithm of Sender's key.
	SigScheme SignatureScheme
	// Signature is the post-quantum signature over SignBytes(t).
	Signature []byte
}

// ErrWrongSender is returned when a signature recovers/validates against a
// public key that does not hash to the declared Sender address.
var ErrWrongSender = errors.New("protocol: signer does not match sender address")

// Marshal encodes the transaction, including the signature, in canonical form.
func (t *Transaction) Marshal() []byte {
	var b []byte
	b = append(b, t.Sender[:]...)
	b = PutUint64(b, t.Nonce)
	b = append(b, t.Kind)
	b = append(b, t.To[:]...)
	b = PutUint64(b, t.Amount)
	b = PutUint64(b, t.Fee)
	b = PutBytes(b, t.Payload)
	b = append(b, byte(t.SigScheme))
	b = PutBytes(b, t.Signature)
	return b
}

// Unmarshal decodes a transaction and verifies the encoding is unambiguous.
func (t *Transaction) Unmarshal(data []byte) error {
	r := NewReader(data)
	var err error
	var sender, to []byte
	if sender, err = r.Fixed(AddressSize); err != nil {
		return err
	}
	copy(t.Sender[:], sender)
	if t.Nonce, err = r.Uint64(); err != nil {
		return err
	}
	if t.Kind, err = r.Uint8(); err != nil {
		return err
	}
	if to, err = r.Fixed(AddressSize); err != nil {
		return err
	}
	copy(t.To[:], to)
	if t.Amount, err = r.Uint64(); err != nil {
		return err
	}
	if t.Fee, err = r.Uint64(); err != nil {
		return err
	}
	if t.Payload, err = r.Bytes(); err != nil {
		return err
	}
	scheme, err := r.Uint8()
	if err != nil {
		return err
	}
	t.SigScheme = SignatureScheme(scheme)
	if t.Signature, err = r.Bytes(); err != nil {
		return err
	}
	if r.Remaining() != 0 {
		return ErrTrailingBytes
	}
	return nil
}

// SignBytes returns the canonical byte string that a signature must cover:
// domain tag, chain ID, the unsigned transaction fields, and the Merkle
// placeholder. Signatures never sign themselves.
func (t *Transaction) SignBytes() []byte {
	var b []byte
	b = append(b, "pq-tx-v1:"...)
	b = append(b, ChainID...)
	b = append(b, 0)
	b = append(b, t.Sender[:]...)
	b = PutUint64(b, t.Nonce)
	b = append(b, t.Kind)
	b = append(b, t.To[:]...)
	b = PutUint64(b, t.Amount)
	b = PutUint64(b, t.Fee)
	b = PutBytes(b, t.Payload)
	b = append(b, byte(t.SigScheme))
	return b
}

// Hash returns the transaction hash (of the full signed encoding).
func (t *Transaction) Hash() Hash {
	return HashBytes(t.Marshal())
}
