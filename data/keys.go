package data

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/Sirupsen/logrus"
	"github.com/jfrazelle/go/canonical/json"
)

// PublicKey is the necessary interface for public keys
type PublicKey interface {
	ID() string
	Algorithm() KeyAlgorithm
	Public() PublicKey
}

// PrivateKey adds the ability to access the private key
type PrivateKey interface {
	PublicKey // keep this first to prefer PublicKey.Public over Crypto.Signer.Public
	Private() ([]byte, error)
	crypto.Signer
}

// KeyPair holds the public and private key bytes
type KeyPair struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

// TUFKey is the structure used for both public and private keys in TUF.
// Normally it would make sense to use a different structures for public and
// private keys, but that would change the key ID algorithm (since the canonical
// JSON would be different). This structure should normally be accessed through
// the PublicKey or PrivateKey interfaces.
type TUFKey struct {
	id    string
	Type  KeyAlgorithm `json:"keytype"`
	Value KeyPair      `json:"keyval"`
}

// PrivateTUFKey implements the private key interface
type PrivateTUFKey struct {
	TUFKey // keep this first to prefer TUFKey.Public over crypto.Signer.Public
	crypto.Signer
}

// NewPrivateKey instantiates a new TUFKey with the private key component
// populated
func NewPrivateKey(algorithm KeyAlgorithm, public []byte, private crypto.Signer) PrivateKey {
	return &PrivateTUFKey{
		TUFKey: TUFKey{
			Type: algorithm,
			Value: KeyPair{
				Public:  public,
				Private: private,
			},
		},
	}
}

// Algorithm returns the algorithm of the key
func (k TUFKey) Algorithm() KeyAlgorithm {
	return k.Type
}

// ID efficiently generates if necessary, and caches the ID of the key
func (k *TUFKey) ID() string {
	if k.id == "" {
		pubK := NewPublicKey(k.Algorithm(), k.Public())
		data, err := json.MarshalCanonical(&pubK)
		if err != nil {
			logrus.Error("Error generating key ID:", err)
		}
		digest := sha256.Sum256(data)
		k.id = hex.EncodeToString(digest[:])
	}
	return k.id
}

// Public returns the public bytes
func (k TUFKey) Public() []byte {
	return k.Value.Public
}

func (k PrivateTUFKey) Sign(random io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if rand == nil {
		rand = rand.Reader
	}
	return k.Signer.Sign(rand, msg, opts)
}

// NewPublicKey instantiates a new TUFKey where the private bytes are
// guaranteed to be nil
func NewPublicKey(algorithm KeyAlgorithm, public []byte) PublicKey {
	return &TUFKey{
		Type: algorithm,
		Value: KeyPair{
			Public:  public,
			Private: nil,
		},
	}
}

type ECDSAPrivateKey struct {
	ecdsa.PrivateKey
}

func (k ECDSAPrivateKey) Sign(random io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sigASN1, err := k.PrivateKey.Sign(random, msg, opts)
	// Use the ECDSA key to sign the data
	sig := struct {
		R *big.Int
		S *big.Int
	}{}
	_, err := asn1.Unmarshal(sigASN1, &sig)
	if err != nil {
		return nil, err
	}

	rBytes, sBytes := sig.R.Bytes(), sig.S.Bytes()
	octetLength := (k.PrivateKey.Params().BitSize + 7) >> 3

	// MUST include leading zeros in the output
	rBuf := make([]byte, octetLength-len(rBytes), octetLength)
	sBuf := make([]byte, octetLength-len(sBytes), octetLength)

	rBuf = append(rBuf, rBytes...)
	sBuf = append(sBuf, sBytes...)

	return append(rBuf, sBuf...), nil
}

func (k ECDSAPrivateKey) Private() ([]byte, error) {
	ecdsaPrivKeyBytes, err := x509.MarshalECPrivateKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %v", err)
	}
	return ecdsaPrivKeyBytes, nil
}

type RSAPrivateKey struct {
	rsa.PrivateKey
}

func (k RSAPrivateKey) Private() ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(rsaPrivKey), nil
}
